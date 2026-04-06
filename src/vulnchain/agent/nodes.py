"""LangGraph node functions for the Vulnchain scan pipeline."""

import json
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from vulnchain.agent.prompts import (
    ATTACK_CHAIN_PROMPT,
    LLM_CODE_REVIEW_PROMPT,
    THREAT_MODEL_PROMPT,
)
from vulnchain.agent.state import ScanState
from vulnchain.analysis.ai_code_detector import detect_ai_code
from vulnchain.analysis.ast_analyzer import analyze_files
from vulnchain.analysis.dependency_scanner import scan_dependencies
from vulnchain.analysis.joern_runner import run_all_joern_queries
from vulnchain.analysis.semgrep_scanner import run_semgrep
from vulnchain.config import get_settings
from vulnchain.ingestion.repo import (
    clone_repo,
    collect_commit_history,
    collect_source_files,
    open_local_repo,
)

logger = logging.getLogger(__name__)

# Severity ordering for sorting (higher = worse)
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# File patterns that indicate high-risk code worth LLM review
_HIGH_RISK_PATTERNS = re.compile(
    r"(login|auth|admin|upload|payment|checkout|password|register|session|token|reset|"
    r"user|account|profile|config|settings|webhook|api|oauth|jwt)",
    re.IGNORECASE,
)

# Max tokens — scale based on analysis complexity
_LLM_MAX_TOKENS = 8192

# Max source code characters to send per file in LLM review
_MAX_CODE_CHARS = 12_000


def _get_llm():
    from langchain_anthropic import ChatAnthropic

    settings = get_settings()
    return ChatAnthropic(
        model=settings.llm_model,
        anthropic_api_key=settings.anthropic_api_key,
        max_tokens=_LLM_MAX_TOKENS,
        temperature=0,
    )


def _extract_json(content: str) -> str:
    """Robustly extract JSON from LLM response, handling markdown fences."""
    content = content.strip()
    # Strip ```json ... ``` or ``` ... ```
    if content.startswith("```"):
        match = re.search(r"```(?:json)?\s*([\s\S]+?)```", content)
        if match:
            return match.group(1).strip()
    return content


def clone_repo_node(state: ScanState) -> dict[str, Any]:
    logger.info("[clone_repo] scan_id=%s repo=%s", state["scan_id"], state["repo_url"])
    try:
        is_local = state.get("is_local", False)
        if is_local:
            repo_path = open_local_repo(state["repo_url"], state["scan_id"])
        else:
            repo_path = clone_repo(state["repo_url"], state["scan_id"])

        source_files = collect_source_files(repo_path)
        commit_history = collect_commit_history(repo_path)
        logger.info(
            "[clone_repo] collected %d files, %d commits",
            len(source_files),
            len(commit_history),
        )
        return {
            "repo_path": str(repo_path),
            "source_files": source_files,
            "commit_history": commit_history,
            "error": None,
        }
    except Exception as exc:
        logger.error("[clone_repo] failed: %s", exc)
        return {"error": str(exc), "repo_path": "", "source_files": [], "commit_history": []}


def parse_ast_node(state: ScanState) -> dict[str, Any]:
    logger.info("[parse_ast] analyzing %d files", len(state["source_files"]))
    try:
        return {"ast_results": analyze_files(state["source_files"])}
    except Exception as exc:
        logger.error("[parse_ast] failed: %s", exc)
        return {"ast_results": [], "error": str(exc)}


def run_semgrep_node(state: ScanState) -> dict[str, Any]:
    logger.info("[run_semgrep] scanning %s", state["repo_path"])
    try:
        return {"semgrep_findings": run_semgrep(state["repo_path"])}
    except Exception as exc:
        logger.error("[run_semgrep] failed: %s", exc)
        return {"semgrep_findings": [], "error": str(exc)}


def detect_ai_code_node(state: ScanState) -> dict[str, Any]:
    logger.info("[detect_ai_code] analyzing %d files", len(state["source_files"]))
    try:
        return {"ai_code_segments": detect_ai_code(state["source_files"], state["commit_history"])}
    except Exception as exc:
        logger.error("[detect_ai_code] failed: %s", exc)
        return {"ai_code_segments": [], "error": str(exc)}


def run_joern_node(state: ScanState) -> dict[str, Any]:
    logger.info("[run_joern] scanning %s", state["repo_path"])
    try:
        return {"joern_findings": run_all_joern_queries(state["repo_path"])}
    except Exception as exc:
        logger.error("[run_joern] failed: %s", exc)
        return {"joern_findings": [], "error": str(exc)}


def scan_dependencies_node(state: ScanState) -> dict[str, Any]:
    """
    Scan dependency manifests and query OSV API for known CVEs.

    Detects:
    - Exact framework/runtime versions (Next.js 14.2.3, Laravel 10.x, Django 4.2, etc.)
    - Known CVEs in installed packages via the free OSV API (no auth required)
    - Tech stack profile used to enrich LLM prompts
    """
    logger.info("[scan_dependencies] scanning %s", state["repo_path"])
    try:
        dep_findings, tech_profile = scan_dependencies(state["repo_path"])
        tech_dict = {
            "languages": tech_profile.languages,
            "frameworks": tech_profile.frameworks,
            "databases": tech_profile.databases,
            "package_counts": tech_profile.package_counts,
            "summary": tech_profile.to_summary(),
        }
        logger.info(
            "[scan_dependencies] %d CVEs found | tech: %s",
            len(dep_findings),
            tech_profile.to_summary().replace("\n", "; "),
        )
        return {"dependency_findings": dep_findings, "tech_profile": tech_dict}
    except Exception as exc:
        logger.error("[scan_dependencies] failed: %s", exc)
        return {"dependency_findings": [], "tech_profile": {}, "error": str(exc)}


def _number_code_lines(code: str) -> str:
    """Prefix each source line with its 1-based line number for LLM accuracy."""
    lines = code.split("\n")
    return "\n".join(f"{i + 1:4d} | {line}" for i, line in enumerate(lines))


def _anchor_line_number(code: str, finding: dict[str, Any]) -> dict[str, Any]:
    """
    Validate and correct LLM-reported line numbers against actual file content.

    Strategy:
    1. Check if `evidence` snippet exists near the reported line (±15 lines)
    2. If not, do a full-file search for the first 40 chars of the evidence
    3. Return corrected finding dict (shallow copy)
    """
    evidence = (finding.get("evidence") or "").strip()
    reported_line = finding.get("line", 0)

    if not evidence or len(evidence) < 8:
        return finding  # not enough evidence to anchor

    lines = code.split("\n")
    anchor = evidence[:40].strip()

    # Fast path: check reported line ± 15
    lo = max(0, reported_line - 16)
    hi = min(len(lines), reported_line + 15)
    for i in range(lo, hi):
        if anchor in lines[i]:
            if i + 1 != reported_line:
                logger.debug("[anchor_line] corrected %d → %d", reported_line, i + 1)
            return {**finding, "line": i + 1}

    # Slow path: full file scan
    for i, line in enumerate(lines):
        if anchor in line:
            logger.debug("[anchor_line] full-scan corrected %d → %d", reported_line, i + 1)
            return {**finding, "line": i + 1}

    # Cannot anchor — keep as-is but add a flag
    return {**finding, "line_unverified": True}


def _select_files_for_llm_review(state: ScanState) -> list[dict[str, Any]]:
    """
    Select the highest-risk files for LLM direct code review.

    Priority:
    1. Files with critical/high severity static findings
    2. Files whose names match high-risk patterns (auth, upload, admin, etc.)

    Returns list of {path, language, findings_count} sorted by risk, capped at 6 files.
    """
    semgrep = state.get("semgrep_findings", [])
    joern = state.get("joern_findings", [])

    # Count findings per file, weighted by severity
    file_score: dict[str, float] = defaultdict(float)
    file_findings: dict[str, list[str]] = defaultdict(list)

    for f in semgrep:
        weight = _SEV_ORDER.get(f.severity, 1) * 2  # semgrep weighted x2
        file_score[f.file_path] += weight
        if f.severity in ("critical", "high"):
            file_findings[f.file_path].append(f"[{f.severity.upper()}] {f.rule_id}: {f.message[:80]}")

    for f in joern:
        weight = _SEV_ORDER.get(f.severity, 1)
        file_score[f.file_path] += weight
        if f.severity in ("critical", "high"):
            file_findings[f.file_path].append(f"[{f.severity.upper()}] {f.rule_id}: {f.method_name}")

    # Build a lookup from path string → SourceFile for efficient access
    sf_by_path: dict[str, Any] = {}
    for sf in state.get("source_files", []):
        fp = str(sf.path) if hasattr(sf, "path") else sf.get("path", "")
        sf_by_path[fp] = sf

    # Also add high-risk files by name even if no findings yet
    for fp in sf_by_path:
        if _HIGH_RISK_PATTERNS.search(Path(fp).name) and fp not in file_score:
            file_score[fp] = 0.5  # low baseline score so they appear at bottom

    # Sort by score descending, cap at 6 files
    ranked = sorted(file_score.items(), key=lambda x: x[1], reverse=True)[:6]

    results = []
    for fp, score in ranked:
        sf = sf_by_path.get(fp)
        lang = sf.language if sf and hasattr(sf, "language") else "unknown"
        results.append(
            {
                "path": fp,
                "language": lang,
                "score": score,
                "findings": file_findings.get(fp, []),
            }
        )
    return results


def llm_code_review_node(state: ScanState) -> dict[str, Any]:
    """
    LLM direct code review: send actual source code of highest-risk files
    to Claude for context-aware vulnerability detection.

    Catches what static analysis misses:
    - Business logic flaws
    - CSRF (missing token validation)
    - Insecure direct object references
    - Second-order injection paths
    - Authorization logic errors
    """
    logger.info("[llm_code_review] selecting high-risk files for LLM review")
    try:
        llm = _get_llm()
        files_to_review = _select_files_for_llm_review(state)

        if not files_to_review:
            logger.info("[llm_code_review] no files selected")
            return {"llm_review_findings": []}

        all_findings: list[dict[str, Any]] = []

        # Build source content lookup from state to avoid re-reading files
        sf_content: dict[str, str] = {}
        for sf in state.get("source_files", []):
            fp_key = str(sf.path) if hasattr(sf, "path") else sf.get("path", "")
            sf_content[fp_key] = sf.content if hasattr(sf, "content") else sf.get("content", "")

        for file_info in files_to_review:
            fp = file_info["path"]
            code = sf_content.get(fp, "")
            if not code:
                try:
                    code = Path(fp).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

            if len(code) > _MAX_CODE_CHARS:
                code = code[:_MAX_CODE_CHARS] + "\n... [truncated]"

            # Send numbered lines so Claude reports accurate line numbers
            numbered_code = _number_code_lines(code)

            existing = "\n".join(file_info["findings"]) or "None"
            prompt = LLM_CODE_REVIEW_PROMPT.format(
                file_path=fp,
                language=file_info["language"],
                existing_findings=existing,
                source_code=numbered_code,
            )

            logger.info("[llm_code_review] reviewing %s (score=%.1f)", fp, file_info["score"])
            try:
                response = llm.invoke(prompt)
                content = _extract_json(response.content if hasattr(response, "content") else str(response))
                data = json.loads(content)
                for finding in data.get("findings", []):
                    finding["file_path"] = fp
                    finding["source"] = "llm_review"
                    # Anchor line number against actual code to fix LLM drift
                    finding = _anchor_line_number(code, finding)
                    # Only keep findings with meaningful severity
                    if finding.get("severity", "low") in ("critical", "high", "medium"):
                        all_findings.append(finding)
            except (json.JSONDecodeError, Exception) as exc:
                logger.warning("[llm_code_review] failed for %s: %s", fp, exc)
                continue

        logger.info(
            "[llm_code_review] found %d LLM findings across %d files",
            len(all_findings),
            len(files_to_review),
        )
        return {"llm_review_findings": all_findings}

    except Exception as exc:
        logger.error("[llm_code_review] failed: %s", exc)
        return {"llm_review_findings": [], "error": str(exc)}


def _build_architecture_summary(state: ScanState) -> str:
    all_endpoints = []
    all_classes = []
    for r in state.get("ast_results", []):
        all_endpoints.extend(r.api_endpoints)
        all_classes.extend(r.class_names)

    tech = state.get("tech_profile") or {}
    dep_findings = state.get("dependency_findings", [])

    lines = [
        f"Repository: {state['repo_url']}",
        f"Source files analyzed: {len(state.get('source_files', []))}",
    ]

    # Technology stack context — helps LLM reason about version-specific issues
    if tech.get("summary"):
        lines.append("")
        lines.append("=== Technology Stack ===")
        lines.append(tech["summary"])

    # Known CVEs in dependencies — critical context for threat modeling
    if dep_findings:
        crit_high = [f for f in dep_findings if f.severity in ("critical", "high")]
        lines.append("")
        lines.append(f"=== Known Dependency CVEs ({len(dep_findings)} total, {len(crit_high)} critical/high) ===")
        for f in sorted(dep_findings, key=lambda x: _SEV_ORDER.get(x.severity, 0), reverse=True)[:20]:
            fixed = f" (fixed in {f.fixed_version})" if f.fixed_version else " (no fix available)"
            lines.append(
                f"  [{f.severity.upper()}] {f.cve_id} {f.package_name}@{f.installed_version}{fixed}: {f.title}"
            )

    lines += [
        "",
        f"Classes/types: {', '.join(all_classes[:50])}",
        "",
        "API Endpoints (all detected):",
    ]
    for ep in all_endpoints[:100]:
        auth = "PROTECTED" if ep.has_auth_decorator else "UNPROTECTED"
        lines.append(f"  [{auth}] {ep.method} {ep.route} → {ep.handler_name}:{ep.line}")
    return "\n".join(lines)


def _sort_findings_by_severity(findings: list, severity_attr: str = "severity") -> list:
    return sorted(findings, key=lambda f: _SEV_ORDER.get(getattr(f, severity_attr, "medium"), 1), reverse=True)


def _build_findings_summary(state: ScanState) -> str:
    semgrep = _sort_findings_by_severity(state.get("semgrep_findings", []))
    joern = _sort_findings_by_severity(state.get("joern_findings", []))
    ai_segs = state.get("ai_code_segments", [])
    llm_review = state.get("llm_review_findings", [])

    total = len(semgrep) + len(joern)
    lines = [f"Total static analysis findings: {total}"]

    if total > 100:
        logger.warning("[findings_summary] %d findings; showing top 40 per scanner (sorted by severity)", total)

    if semgrep:
        lines.append(f"\nSemgrep findings (top 40 of {len(semgrep)}, sorted by severity):")
        for f in semgrep[:40]:
            lines.append(f"  [{f.severity.upper()}] {f.rule_id}: {f.file_path}:{f.line_start} — {f.message[:120]}")

    if joern:
        lines.append(f"\nJoern CPG findings (top 40 of {len(joern)}, sorted by severity):")
        for f in joern[:40]:
            lines.append(f"  [{f.severity.upper()}] {f.rule_id}: {f.file_path}:{f.line} — {f.method_name}")

    if llm_review:
        lines.append(f"\nLLM direct code review findings ({len(llm_review)}):")
        for f in sorted(llm_review, key=lambda x: _SEV_ORDER.get(x.get("severity", "medium"), 1), reverse=True)[:20]:
            lines.append(
                f"  [{f.get('severity', '?').upper()}] {f.get('cwe_id', '?')} "
                f"{f.get('file_path', '?')}:{f.get('line', '?')} — {f.get('title', '?')}"
            )

    if ai_segs:
        lines.append(f"\nAI-generated code segments: {len(ai_segs)}")
        for s in ai_segs[:5]:
            lines.append(f"  {s.file_path} (confidence={s.confidence:.0%}): {'; '.join(s.signals[:2])}")

    return "\n".join(lines)


def generate_threat_model_node(state: ScanState) -> dict[str, Any]:
    logger.info("[generate_threat_model] invoking LLM")
    try:
        llm = _get_llm()
        prompt = THREAT_MODEL_PROMPT.format(
            architecture_summary=_build_architecture_summary(state),
            findings_summary=_build_findings_summary(state),
        )
        response = llm.invoke(prompt)
        content = _extract_json(response.content if hasattr(response, "content") else str(response))
        return {"threat_model": json.loads(content)}
    except json.JSONDecodeError as exc:
        logger.error("[generate_threat_model] LLM returned invalid JSON: %s", exc)
        return {
            "threat_model": {
                "threat_model": [],
                "high_value_targets": [],
                "attack_surface_summary": "",
            }
        }
    except Exception as exc:
        logger.error("[generate_threat_model] failed: %s", exc)
        return {"threat_model": None, "error": str(exc)}


def synthesize_attack_chains_node(state: ScanState) -> dict[str, Any]:
    logger.info("[synthesize_attack_chains] invoking LLM")
    try:
        llm = _get_llm()

        # Build unified findings list sorted by severity, cap at 100
        findings: list[dict] = []
        for f in _sort_findings_by_severity(state.get("semgrep_findings", [])):
            findings.append(
                {
                    "id": f.rule_id,
                    "source": "semgrep",
                    "severity": f.severity,
                    "file": f.file_path,
                    "line": f.line_start,
                    "message": f.message,
                }
            )
        for f in _sort_findings_by_severity(state.get("joern_findings", [])):
            findings.append(
                {
                    "id": f.rule_id,
                    "source": "joern",
                    "severity": f.severity,
                    "file": f.file_path,
                    "line": f.line,
                    "message": f"CPG: {f.method_name}",
                }
            )
        for f in sorted(
            state.get("llm_review_findings", []),
            key=lambda x: _SEV_ORDER.get(x.get("severity", "medium"), 1),
            reverse=True,
        ):
            findings.append(
                {
                    "id": f.get("cwe_id", "llm-review"),
                    "source": "llm_review",
                    "severity": f.get("severity", "medium"),
                    "file": f.get("file_path", "?"),
                    "line": f.get("line", 0),
                    "message": f.get("title", "?"),
                }
            )
        # Include dependency CVEs — often chain with code-level findings
        for f in sorted(
            state.get("dependency_findings", []),
            key=lambda x: _SEV_ORDER.get(x.severity, 0),
            reverse=True,
        )[:20]:
            fixed = f" (fixed: {f.fixed_version})" if f.fixed_version else ""
            findings.append(
                {
                    "id": f.cve_id,
                    "source": "dependency",
                    "severity": f.severity,
                    "file": f.manifest_file,
                    "line": 0,
                    "message": f"{f.package_name}@{f.installed_version}: {f.title}{fixed}",
                }
            )

        if len(findings) > 100:
            logger.info("[synthesize_attack_chains] capping findings at 100 (have %d)", len(findings))
        cap = findings[:100]

        prompt = ATTACK_CHAIN_PROMPT.format(
            findings_json=json.dumps(cap, indent=2),
            threat_model_json=json.dumps(state.get("threat_model") or {}, indent=2),
        )
        response = llm.invoke(prompt)
        content = _extract_json(response.content if hasattr(response, "content") else str(response))

        chain_data = json.loads(content)
        from vulnchain.analysis.models import AttackChain

        chains = [
            AttackChain(
                title=c.get("title", "Unnamed chain"),
                steps=c.get("steps", []),
                finding_ids=c.get("finding_ids", []),
                combined_severity=c.get("combined_severity", "high"),
                individual_severities=c.get("individual_severities", []),
                business_impact=c.get("business_impact", ""),
                cvss_estimate=float(c.get("cvss_estimate", 0.0)),
                proof_of_concept=c.get("proof_of_concept", ""),
            )
            for c in chain_data.get("attack_chains", [])
        ]
        return {"attack_chains": chains}
    except json.JSONDecodeError as exc:
        logger.error("[synthesize_attack_chains] LLM returned invalid JSON: %s", exc)
        return {"attack_chains": []}
    except Exception as exc:
        logger.error("[synthesize_attack_chains] failed: %s", exc)
        return {"attack_chains": [], "error": str(exc)}


def generate_report_node(state: ScanState) -> dict[str, Any]:
    logger.info("[generate_report] generating reports for scan %s", state["scan_id"])
    try:
        from vulnchain.reporting.formatter import generate_markdown, generate_sarif

        return {
            "report_markdown": generate_markdown(state),
            "report_sarif": generate_sarif(state),
        }
    except Exception as exc:
        logger.error("[generate_report] failed: %s", exc)
        return {"report_markdown": f"Report generation failed: {exc}", "report_sarif": {}}


def handle_error_node(state: ScanState) -> dict[str, Any]:
    error = state.get("error", "Unknown error")
    logger.error("[handle_error] scan %s failed: %s", state["scan_id"], error)
    return {"report_markdown": f"# Scan Failed\n\nError: {error}\n", "report_sarif": {}}
