"""
Dependency vulnerability scanner.

Parses package manifests (package.json, requirements.txt, composer.json, go.mod)
to extract exact dependency versions, then queries the OSV API (free, no auth)
to find known CVEs for each package@version combination.

Also builds a tech_profile dict with exact framework/runtime versions for use
in LLM prompts.
"""

import json
import logging
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT = 20  # seconds
OSV_BATCH_SIZE = 100  # max queries per request

# Map manifest filename patterns to ecosystem names used by OSV
_ECOSYSTEM_MAP = {
    "package.json": "npm",
    "composer.json": "Packagist",
    "requirements.txt": "PyPI",
    "requirements-dev.txt": "PyPI",
    "requirements-test.txt": "PyPI",
    "Pipfile": "PyPI",
    "go.mod": "Go",
    "go.sum": "Go",
    "Gemfile": "RubyGems",
    "pubspec.yaml": "Pub",
    "pyproject.toml": "PyPI",
    "Cargo.toml": "crates.io",
    "pom.xml": "Maven",
}

# Framework name → (manifest file, json path or regex pattern)
_FRAMEWORK_DETECTORS = [
    # JavaScript / TypeScript frameworks
    ("next.js",        "package.json",    ["dependencies", "next"]),
    ("react",          "package.json",    ["dependencies", "react"]),
    ("vue",            "package.json",    ["dependencies", "vue"]),
    ("angular",        "package.json",    ["dependencies", "@angular/core"]),
    ("express",        "package.json",    ["dependencies", "express"]),
    ("fastify",        "package.json",    ["dependencies", "fastify"]),
    ("nuxt",           "package.json",    ["dependencies", "nuxt"]),
    ("svelte",         "package.json",    ["devDependencies", "svelte"]),
    ("typescript",     "package.json",    ["devDependencies", "typescript"]),
    # PHP frameworks
    ("laravel",        "composer.json",   ["require", "laravel/framework"]),
    ("symfony",        "composer.json",   ["require", "symfony/framework-bundle"]),
    ("wordpress",      "composer.json",   ["require", "johnpbloch/wordpress"]),
    ("codeigniter",    "composer.json",   ["require", "codeigniter4/framework"]),
    ("slim",           "composer.json",   ["require", "slim/slim"]),
    # Python frameworks
    ("django",         "requirements.txt", None),
    ("flask",          "requirements.txt", None),
    ("fastapi",        "requirements.txt", None),
    ("sqlalchemy",     "requirements.txt", None),
    ("celery",         "requirements.txt", None),
    # Go frameworks
    ("gin",            "go.mod",          None),
    ("echo",           "go.mod",          None),
    ("fiber",          "go.mod",          None),
]


@dataclass
class DependencyFinding:
    """A known CVE found in a project dependency."""
    package_name: str
    installed_version: str
    ecosystem: str
    cve_id: str          # e.g. "CVE-2023-12345" or OSV ID like "GHSA-xxxx"
    severity: str        # critical / high / medium / low
    cvss_score: float
    title: str
    description: str
    fixed_version: str   # earliest version that fixes this
    manifest_file: str   # which file declared this package


@dataclass
class TechProfile:
    """Technology stack detected in the repository."""
    languages: dict[str, str] = field(default_factory=dict)    # lang → version
    frameworks: dict[str, str] = field(default_factory=dict)   # framework → version
    databases: list[str] = field(default_factory=list)
    package_counts: dict[str, int] = field(default_factory=dict)  # ecosystem → count
    manifest_files: list[str] = field(default_factory=list)

    def to_summary(self) -> str:
        """Human-readable summary for LLM prompts."""
        parts = []
        if self.languages:
            parts.append("Runtime versions: " + ", ".join(
                f"{lang} {ver}" for lang, ver in self.languages.items()
            ))
        if self.frameworks:
            parts.append("Frameworks: " + ", ".join(
                f"{fw} {ver}" for fw, ver in self.frameworks.items()
            ))
        if self.databases:
            parts.append("Databases detected: " + ", ".join(self.databases))
        if self.package_counts:
            parts.append("Dependencies: " + ", ".join(
                f"{eco} ({n} packages)" for eco, n in self.package_counts.items()
            ))
        return "\n".join(parts) if parts else "No technology profile detected"


def scan_dependencies(repo_path: str) -> tuple[list[DependencyFinding], TechProfile]:
    """
    Main entry point. Parses all manifests, builds tech profile, queries OSV.

    Returns:
        (dependency_findings, tech_profile)
    """
    repo = Path(repo_path)
    packages: list[tuple[str, str, str, str]] = []  # (name, version, ecosystem, manifest)
    tech = TechProfile()

    # --- Parse manifests ---
    _parse_package_json_files(repo, packages, tech)
    _parse_requirements_files(repo, packages, tech)
    _parse_composer_json_files(repo, packages, tech)
    _parse_go_mod_files(repo, packages, tech)
    _parse_pyproject_toml_files(repo, packages, tech)
    _detect_runtime_versions(repo, tech)
    _detect_framework_versions(repo, tech)
    _detect_databases(repo, tech)

    if not packages:
        logger.info("[dependency_scanner] no packages found in %s", repo_path)
        return [], tech

    for eco, pkgs in _group_by_ecosystem(packages).items():
        tech.package_counts[eco] = len(pkgs)

    logger.info("[dependency_scanner] querying OSV for %d packages", len(packages))
    findings = _query_osv_batch(packages)
    logger.info("[dependency_scanner] found %d known CVEs", len(findings))
    return findings, tech


# ──────────────────────────────────────────────────────────────────────────────
# Manifest parsers
# ──────────────────────────────────────────────────────────────────────────────

def _parse_package_json_files(
    repo: Path,
    packages: list,
    tech: TechProfile,
) -> None:
    for pj in repo.rglob("package.json"):
        if _is_skipped_dir(pj):
            continue
        tech.manifest_files.append(str(pj.relative_to(repo)))
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue

        for dep_key in ("dependencies", "devDependencies", "peerDependencies"):
            for name, ver_raw in data.get(dep_key, {}).items():
                ver = _clean_semver(ver_raw)
                if ver:
                    packages.append((name, ver, "npm", str(pj.relative_to(repo))))

        # Extract Node.js engine version
        engines = data.get("engines", {})
        if "node" in engines:
            tech.languages["node"] = _clean_semver(engines["node"]) or engines["node"]


def _parse_requirements_files(
    repo: Path,
    packages: list,
    tech: TechProfile,
) -> None:
    patterns = ["requirements*.txt", "constraints*.txt"]
    for pattern in patterns:
        for rf in repo.rglob(pattern):
            if _is_skipped_dir(rf):
                continue
            tech.manifest_files.append(str(rf.relative_to(repo)))
            try:
                for line in rf.read_text(encoding="utf-8", errors="replace").splitlines():
                    name, ver = _parse_pip_requirement(line)
                    if name and ver:
                        packages.append((name, ver, "PyPI", str(rf.relative_to(repo))))
            except OSError:
                continue


def _parse_composer_json_files(
    repo: Path,
    packages: list,
    tech: TechProfile,
) -> None:
    for cf in repo.rglob("composer.json"):
        if _is_skipped_dir(cf) or "vendor" in cf.parts:
            continue
        tech.manifest_files.append(str(cf.relative_to(repo)))
        try:
            data = json.loads(cf.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue

        for dep_key in ("require", "require-dev"):
            for name, ver_raw in data.get(dep_key, {}).items():
                if name == "php" or name.startswith("ext-"):
                    # PHP runtime version
                    if name == "php":
                        tech.languages["php"] = _clean_semver(ver_raw) or ver_raw
                    continue
                ver = _clean_semver(ver_raw)
                if ver:
                    packages.append((name, ver, "Packagist", str(cf.relative_to(repo))))


def _parse_go_mod_files(
    repo: Path,
    packages: list,
    tech: TechProfile,
) -> None:
    for gm in repo.rglob("go.mod"):
        if _is_skipped_dir(gm):
            continue
        tech.manifest_files.append(str(gm.relative_to(repo)))
        try:
            text = gm.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Go runtime version
        go_ver = re.search(r"^go\s+(\S+)", text, re.MULTILINE)
        if go_ver:
            tech.languages["go"] = go_ver.group(1)

        # Dependencies
        for m in re.finditer(r"^\s+(\S+)\s+(v[\d.]+\S*)", text, re.MULTILINE):
            packages.append((m.group(1), m.group(2).lstrip("v"), "Go",
                             str(gm.relative_to(repo))))


def _parse_pyproject_toml_files(
    repo: Path,
    packages: list,
    tech: TechProfile,
) -> None:
    for pp in repo.rglob("pyproject.toml"):
        if _is_skipped_dir(pp):
            continue
        tech.manifest_files.append(str(pp.relative_to(repo)))
        try:
            text = pp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Extract python requires
        py_ver = re.search(r'python_requires\s*=\s*["\']([^"\']+)["\']', text)
        if py_ver:
            tech.languages["python"] = py_ver.group(1)

        # Extract dependencies (basic regex, not full TOML parse)
        for m in re.finditer(r'"([a-zA-Z0-9_\-\.]+)[>=<!\s]*([0-9][^\s"\']*)"', text):
            name = m.group(1)
            ver = _clean_semver(m.group(2))
            if ver and name not in ("python",):
                packages.append((name, ver, "PyPI", str(pp.relative_to(repo))))


# ──────────────────────────────────────────────────────────────────────────────
# Runtime / framework detection
# ──────────────────────────────────────────────────────────────────────────────

def _detect_runtime_versions(repo: Path, tech: TechProfile) -> None:
    """Detect runtime versions from version config files."""
    version_files = {
        ".nvmrc":          ("node", lambda t: t.strip().lstrip("v")),
        ".node-version":   ("node", lambda t: t.strip().lstrip("v")),
        ".python-version": ("python", lambda t: t.strip()),
        ".ruby-version":   ("ruby", lambda t: t.strip()),
        ".go-version":     ("go", lambda t: t.strip()),
        ".tool-versions":  ("multi", _parse_tool_versions),
    }
    for filename, (lang, parser) in version_files.items():
        candidate = repo / filename
        if candidate.exists():
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace").strip()
                if lang == "multi":
                    result = parser(text)
                    if isinstance(result, dict):
                        tech.languages.update(result)
                else:
                    ver = parser(text)
                    if ver and lang not in tech.languages:
                        tech.languages[lang] = ver
            except OSError:
                pass

    # PHP: check for .php-version or Dockerfile FROM php:X.X
    php_ver = repo / ".php-version"
    if php_ver.exists():
        try:
            tech.languages["php"] = php_ver.read_text().strip()
        except OSError:
            pass
    else:
        # Try Dockerfile
        for dockerfile in ["Dockerfile", "Dockerfile.php", "docker/Dockerfile"]:
            df = repo / dockerfile
            if df.exists():
                try:
                    m = re.search(r"FROM\s+php:([\d.]+)", df.read_text())
                    if m and "php" not in tech.languages:
                        tech.languages["php"] = m.group(1)
                        break
                except OSError:
                    pass


def _detect_framework_versions(repo: Path, tech: TechProfile) -> None:
    """Extract exact framework versions from manifests."""
    for fw_name, manifest, json_path in _FRAMEWORK_DETECTORS:
        if json_path is None:
            continue
        for candidate in repo.rglob(manifest):
            if _is_skipped_dir(candidate) or "vendor" in candidate.parts:
                continue
            try:
                data = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            ver_raw = data
            try:
                for key in json_path:
                    ver_raw = ver_raw[key]
                ver = _clean_semver(str(ver_raw))
                if ver and fw_name not in tech.frameworks:
                    tech.frameworks[fw_name] = ver
            except (KeyError, TypeError):
                continue

    # Python frameworks from requirements.txt
    for rf in repo.rglob("requirements*.txt"):
        if _is_skipped_dir(rf):
            continue
        try:
            text = rf.read_text(encoding="utf-8", errors="replace").lower()
            for fw in ("django", "flask", "fastapi", "celery", "sqlalchemy",
                       "tornado", "aiohttp", "starlette"):
                m = re.search(rf"^{fw}[=!<>~^]+([0-9][^\s#]*)", text, re.MULTILINE)
                if m and fw not in tech.frameworks:
                    tech.frameworks[fw] = m.group(1)
        except OSError:
            pass


def _detect_databases(repo: Path, tech: TechProfile) -> None:
    """Heuristically detect database technology from config/package files."""
    db_signals = {
        "postgresql": ["psycopg", "pg", "postgres", "postgresql", "asyncpg"],
        "mysql":      ["mysql", "mysqli", "mysqlclient", "pymysql"],
        "mongodb":    ["mongoose", "mongodb", "pymongo", "motor"],
        "redis":      ["redis", "ioredis", "aioredis"],
        "sqlite":     ["sqlite", "better-sqlite3"],
        "elasticsearch": ["elasticsearch", "elastic"],
    }

    search_files = list(repo.rglob("package.json"))[:5] + \
                   list(repo.rglob("requirements*.txt"))[:5] + \
                   list(repo.rglob("composer.json"))[:5]

    detected = set()
    for f in search_files:
        if _is_skipped_dir(f):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace").lower()
            for db, signals in db_signals.items():
                if any(sig in text for sig in signals):
                    detected.add(db)
        except OSError:
            pass

    tech.databases = sorted(detected)


# ──────────────────────────────────────────────────────────────────────────────
# OSV API
# ──────────────────────────────────────────────────────────────────────────────

def _query_osv_batch(
    packages: list[tuple[str, str, str, str]],
) -> list[DependencyFinding]:
    """Query OSV batch API for all packages. Returns CVE findings."""
    findings: list[DependencyFinding] = []

    for batch_start in range(0, len(packages), OSV_BATCH_SIZE):
        batch = packages[batch_start: batch_start + OSV_BATCH_SIZE]
        queries = [
            {
                "version": ver,
                "package": {"name": name, "ecosystem": eco},
            }
            for name, ver, eco, _ in batch
        ]
        payload = json.dumps({"queries": queries}).encode("utf-8")
        try:
            req = urllib.request.Request(
                OSV_BATCH_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            logger.warning("[dependency_scanner] OSV API error: %s", exc)
            continue

        for i, result in enumerate(data.get("results", [])):
            pkg_name, pkg_ver, ecosystem, manifest_file = batch[i]
            for vuln in result.get("vulns", []):
                finding = _osv_vuln_to_finding(
                    vuln, pkg_name, pkg_ver, ecosystem, manifest_file
                )
                if finding:
                    findings.append(finding)

    return findings


def _osv_vuln_to_finding(
    vuln: dict[str, Any],
    pkg_name: str,
    pkg_ver: str,
    ecosystem: str,
    manifest_file: str,
) -> DependencyFinding | None:
    """Convert an OSV vulnerability record to a DependencyFinding."""
    osv_id = vuln.get("id", "")
    summary = vuln.get("summary", osv_id)
    details = (vuln.get("details", "") or "")[:600]

    # Extract CVE alias if present
    cve_id = osv_id
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    # Extract CVSS score and severity
    cvss_score, severity = _extract_severity(vuln)

    # Extract fixed version
    fixed_ver = _extract_fixed_version(vuln, pkg_ver, ecosystem)

    return DependencyFinding(
        package_name=pkg_name,
        installed_version=pkg_ver,
        ecosystem=ecosystem,
        cve_id=cve_id,
        severity=severity,
        cvss_score=cvss_score,
        title=summary,
        description=details,
        fixed_version=fixed_ver,
        manifest_file=manifest_file,
    )


def _extract_severity(vuln: dict[str, Any]) -> tuple[float, str]:
    """Return (cvss_score, severity_str) from an OSV vulnerability record."""
    # Try CVSS v3 first, then v2
    for sev_entry in vuln.get("severity", []):
        score_str = sev_entry.get("score", "")
        try:
            score = float(score_str)
            return score, _cvss_to_severity(score)
        except (ValueError, TypeError):
            pass

    # Fallback: look in database_specific
    for db_info in vuln.get("database_specific", {}).values():
        if isinstance(db_info, dict):
            severity_label = db_info.get("severity", "")
            if severity_label:
                return 0.0, severity_label.lower()

    # Fallback from affected[].ecosystem_specific
    for affected in vuln.get("affected", []):
        es = affected.get("ecosystem_specific", {})
        severity_label = es.get("severity", "")
        if severity_label:
            return 0.0, severity_label.lower()

    return 0.0, "medium"


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_fixed_version(
    vuln: dict[str, Any],
    installed: str,
    ecosystem: str,
) -> str:
    """Extract the earliest fixed version from OSV affected[].ranges."""
    fixed_versions: list[str] = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    fixed_versions.append(fixed)
    # Return the first fixed version (OSV lists them in order)
    return fixed_versions[0] if fixed_versions else ""


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_skipped_dir(path: Path) -> bool:
    skip = {"node_modules", "vendor", ".git", "__pycache__", ".venv", "venv",
            "dist", "build", ".tox", "site-packages"}
    return bool(skip.intersection(set(path.parts)))


def _clean_semver(raw: str) -> str:
    """Strip npm/composer/pip range specifiers and return a bare version."""
    if not raw or not isinstance(raw, str):
        return ""
    # Remove range operators, whitespace, leading v
    ver = re.sub(r"[^0-9.]", "", raw.lstrip("vV^~>=<! ").split()[0])
    # Must look like X or X.Y or X.Y.Z
    if re.match(r"^\d+(\.\d+)*$", ver):
        return ver
    return ""


def _parse_pip_requirement(line: str) -> tuple[str, str]:
    """Parse a single requirements.txt line into (name, version)."""
    line = line.strip()
    if not line or line.startswith(("#", "-", "http", "git+")):
        return "", ""
    # name==version or name>=version etc.
    m = re.match(r"^([A-Za-z0-9_\-\.]+)[>=<!\^~]+([0-9][^\s,;#]*)", line)
    if m:
        return m.group(1).lower(), _clean_semver(m.group(2)) or m.group(2).strip()
    # name only (no version pinned) — skip
    return "", ""


def _parse_tool_versions(text: str) -> dict[str, str]:
    """Parse .tool-versions file (asdf format): 'nodejs 18.12.0'."""
    result: dict[str, str] = {}
    name_map = {"nodejs": "node", "python": "python", "ruby": "ruby", "golang": "go"}
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            tool = name_map.get(parts[0], parts[0])
            result[tool] = parts[1]
    return result


def _group_by_ecosystem(
    packages: list[tuple[str, str, str, str]],
) -> dict[str, list]:
    result: dict[str, list] = {}
    for pkg in packages:
        result.setdefault(pkg[2], []).append(pkg)
    return result
