"""Semgrep subprocess wrapper for static analysis."""

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

from vulnchain.analysis.models import SemgrepFinding
from vulnchain.config import get_settings

logger = logging.getLogger(__name__)

CUSTOM_RULES_DIR = Path(__file__).parent.parent / "semgrep_rules"

_SEVERITY_MAP = {
    "ERROR": "critical",
    "WARNING": "high",
    "INFO": "medium",
    "NOTE": "low",
}


def run_semgrep(repo_path: str) -> list[SemgrepFinding]:
    """
    Run Semgrep against repo_path using local custom rules only.

    The p/ registry rulesets require a paid Semgrep Team plan (exit 7 = auth
    failure). Our taint-mode local rules cover the same CWEs with higher
    accuracy for the supported languages.

    Returns:
        List of SemgrepFinding instances.
    """
    import os

    settings = get_settings()
    timeout = settings.semgrep_timeout_seconds

    cmd: list[str] = ["semgrep", "--config", str(CUSTOM_RULES_DIR)]
    logger.info("Semgrep: using local rules from %s", CUSTOM_RULES_DIR)

    cmd += [
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--max-memory",
        "2000",
        "--timeout",
        "60",
        "--disable-version-check",
        "--metrics=off",
        repo_path,
    ]

    # Remove SEMGREP_APP_TOKEN entirely — setting it to "" still triggers auth
    # checks in some Semgrep versions (exit 7). Deleting the key forces local-only mode.
    env = {k: v for k, v in os.environ.items() if k != "SEMGREP_APP_TOKEN"}
    env["SEMGREP_SEND_METRICS"] = "off"

    logger.info("Running Semgrep on %s", repo_path)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        logger.error("Semgrep timed out after %d seconds", timeout)
        return []
    except FileNotFoundError:
        logger.error("Semgrep not found — install with: pip install semgrep")
        return []

    # 0 = no findings, 1 = findings found, 2 = partial results / parse errors
    # Exit 2 still emits valid JSON with a partial "results" array — parse it.
    if result.returncode not in (0, 1, 2):
        diag = (result.stderr or result.stdout)[:400]
        logger.warning("Semgrep exited %d: %s", result.returncode, diag)
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        diag = (result.stderr or result.stdout)[:400]
        logger.error("Failed to parse Semgrep JSON output: %s — raw: %s", exc, diag)
        return []

    if result.returncode == 2:
        errors = data.get("errors", [])
        logger.warning(
            "Semgrep exited 2 (parse/rule errors) — %d error(s): %s",
            len(errors),
            "; ".join(e.get("message", str(e)) for e in errors[:3]),
        )

    findings: list[SemgrepFinding] = []
    for raw in data.get("results", []):
        try:
            findings.append(_parse_semgrep_finding(raw))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse Semgrep finding: %s", exc)

    logger.info("Semgrep found %d findings", len(findings))
    return findings


def _parse_semgrep_finding(raw: dict[str, Any]) -> SemgrepFinding:
    check_id = raw.get("check_id", "unknown")
    severity_raw = raw.get("extra", {}).get("severity", "WARNING").upper()
    severity = _SEVERITY_MAP.get(severity_raw, "medium")

    start = raw.get("start", {})
    end = raw.get("end", {})
    line_start = start.get("line", 0)
    line_end = end.get("line", line_start)

    message = raw.get("extra", {}).get("message", "No message provided")
    file_path = raw.get("path", "unknown")

    metadata = raw.get("extra", {}).get("metadata", {})
    fix_suggestion = metadata.get("fix") or raw.get("extra", {}).get("fix")

    return SemgrepFinding(
        rule_id=check_id,
        severity=severity,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        message=message,
        fix_suggestion=fix_suggestion,
        raw=raw,
    )
