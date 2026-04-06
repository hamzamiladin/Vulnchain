"""Joern CPG (Code Property Graph) subprocess wrapper."""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from vulnchain.analysis.models import JoernFinding
from vulnchain.config import get_settings

logger = logging.getLogger(__name__)

SCRIPTS_DIR = Path(__file__).parent.parent / "joern_scripts"

_SCRIPT_RULE_MAP = {
    "tainted_sql.sc": "tainted-sql-injection",
    "missing_auth.sc": "missing-authorization",
    "data_leak.sc": "sensitive-data-in-logs",
    "command_injection.sc": "tainted-command-injection",
    "path_traversal.sc": "tainted-path-traversal",
    "ssrf.sc": "tainted-ssrf",
    "insecure_deserialization.sc": "insecure-deserialization",
    "xxe_injection.sc": "xxe-injection",
    "open_redirect.sc": "open-redirect",
    "ldap_injection.sc": "ldap-injection",
    "template_injection.sc": "template-injection-ssti",
    "prototype_pollution.sc": "prototype-pollution",
    "jwt_algorithm_confusion.sc": "jwt-algorithm-confusion",
}

_JAVA_ENV = {
    **os.environ,
    "JAVA_OPTS": "-Xmx2g -Xms512m",
}


def _build_cpg(repo_path: str, cpg_path: str, workspace_dir: str) -> bool:
    """
    Use joern-parse to build a binary CPG from source.

    Returns True on success, False if joern-parse is unavailable or fails.
    """
    settings = get_settings()
    try:
        result = subprocess.run(
            [
                "joern-parse",
                repo_path,
                "--output",
                cpg_path,
            ],
            capture_output=True,
            text=True,
            timeout=settings.joern_timeout_seconds,
            cwd=workspace_dir,
            env=_JAVA_ENV,
        )
    except FileNotFoundError:
        logger.info("joern-parse not found — skipping CPG analysis")
        return False
    except subprocess.TimeoutExpired:
        logger.warning("joern-parse timed out after %d seconds", settings.joern_timeout_seconds)
        return False

    if result.returncode != 0:
        logger.warning(
            "joern-parse exited %d: %s",
            result.returncode,
            (result.stderr or result.stdout)[:500],
        )
        return False

    if not Path(cpg_path).exists():
        logger.warning("joern-parse succeeded but CPG file not found at %s", cpg_path)
        return False

    logger.info("CPG built at %s (%d bytes)", cpg_path, Path(cpg_path).stat().st_size)
    return True


def _run_script_on_cpg(
    script_name: str,
    cpg_path: str,
    workspace_dir: str,
) -> list[dict[str, Any]]:
    """
    Run a single Joern script against a pre-built binary CPG file.
    The script receives `cpgFile` instead of `inputDir`.
    """
    settings = get_settings()
    script_path = SCRIPTS_DIR / script_name

    if not script_path.exists():
        logger.warning("Joern script not found: %s", script_path)
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, dir=workspace_dir) as tmp:
        out_path = tmp.name

    try:
        result = subprocess.run(
            [
                "joern",
                "--script",
                str(script_path),
                "--param",
                f"cpgFile={cpg_path}",
                "--param",
                f"outputFile={out_path}",
            ],
            capture_output=True,
            text=True,
            timeout=settings.joern_timeout_seconds,
            cwd=workspace_dir,
            env=_JAVA_ENV,
        )

        import contextlib

        out = ""
        with contextlib.suppress(OSError):
            out = Path(out_path).read_text(encoding="utf-8").strip()

        if result.returncode not in (0, 1) or (result.returncode != 0 and not out):
            logger.warning(
                "Joern exited %d for %s: %s",
                result.returncode,
                script_name,
                (result.stderr or result.stdout)[:500],
            )
            return []

        if result.returncode != 0:
            logger.info(
                "Joern exited %d for %s but wrote output — parsing",
                result.returncode,
                script_name,
            )

        if not out:
            return []

        data = json.loads(out)
        return data if isinstance(data, list) else []

    except subprocess.TimeoutExpired:
        logger.warning("Joern timed out running %s", script_name)
        return []
    except FileNotFoundError:
        logger.info("joern not installed — skipping %s", script_name)
        return []
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse Joern output for %s: %s", script_name, exc)
        return []


def run_all_joern_queries(repo_path: str) -> list[JoernFinding]:
    """
    Build one CPG from repo_path, then run all analysis scripts against it.

    Uses a temporary workspace that is cleaned up on exit.
    """
    workspace_dir = tempfile.mkdtemp(prefix="joern-ws-")
    cpg_path = str(Path(workspace_dir) / "scan.cpg")

    try:
        if not _build_cpg(repo_path, cpg_path, workspace_dir):
            logger.warning("CPG build failed — Joern analysis skipped")
            return []

        all_findings: list[JoernFinding] = []
        for script_name, rule_id in _SCRIPT_RULE_MAP.items():
            for raw in _run_script_on_cpg(script_name, cpg_path, workspace_dir):
                try:
                    all_findings.append(
                        JoernFinding(
                            rule_id=rule_id,
                            severity=raw.get("severity", "high"),
                            file_path=raw.get("file", "unknown"),
                            line=raw.get("line", 0),
                            method_name=raw.get("method", "unknown"),
                            script=script_name,
                            raw=raw,
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to parse Joern finding: %s", exc)

        logger.info(
            "Joern found %d findings across %d scripts",
            len(all_findings),
            len(_SCRIPT_RULE_MAP),
        )
        return all_findings

    finally:
        shutil.rmtree(workspace_dir, ignore_errors=True)
