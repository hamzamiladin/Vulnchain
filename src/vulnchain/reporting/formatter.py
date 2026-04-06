"""Markdown and SARIF report generation."""

import logging
from datetime import UTC, datetime
from typing import Any

from vulnchain.agent.state import ScanState

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


def generate_markdown(state: ScanState) -> str:
    now = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    repo = state.get("repo_url", "unknown")
    scan_id = state.get("scan_id", "unknown")
    semgrep = state.get("semgrep_findings", [])
    joern = state.get("joern_findings", [])
    ai_segs = state.get("ai_code_segments", [])
    chains = state.get("attack_chains", [])
    threat_model = state.get("threat_model") or {}

    severity_order = ["critical", "high", "medium", "low", "info"]
    counts: dict[str, int] = dict.fromkeys(severity_order, 0)
    for f in semgrep:
        sev = getattr(f, "severity", "info")
        if sev in counts:
            counts[sev] += 1
    for f in joern:
        sev = getattr(f, "severity", "info")
        if sev in counts:
            counts[sev] += 1

    total = len(semgrep) + len(joern)
    lines: list[str] = [
        "# RedTeam Security Report",
        "",
        f"**Repository:** {repo}",
        f"**Scan ID:** `{scan_id}`",
        f"**Generated:** {now}",
        f"**Total Findings:** {total}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for sev in severity_order:
        lines.append(f"| {_SEVERITY_EMOJI.get(sev, '')} {sev.capitalize()} | {counts[sev]} |")

    lines += ["", "---", "", "## Attack Surface", ""]
    atk_summary = threat_model.get("attack_surface_summary", "")
    if atk_summary:
        lines += [atk_summary, ""]
    hvts = threat_model.get("high_value_targets", [])
    if hvts:
        lines.append("**High-Value Targets:**")
        for t in hvts:
            lines.append(f"- {t}")
        lines.append("")

    if chains:
        lines += ["---", "", "## Attack Chains", ""]
        for i, chain in enumerate(chains, 1):
            sev = getattr(chain, "combined_severity", "high")
            cvss = getattr(chain, "cvss_estimate", 0.0)
            lines += [
                f"### {i}. {_SEVERITY_EMOJI.get(sev, '')} {chain.title}",
                "",
                f"**Combined Severity:** {sev.upper()}  ",
                f"**CVSS Estimate:** {cvss}",
                "",
                "**Attack Steps:**",
                "",
            ]
            for step in chain.steps:
                lines.append(f"1. {step}")
            lines += ["", f"**Business Impact:** {chain.business_impact}", ""]
            poc = getattr(chain, "proof_of_concept", "")
            if poc:
                lines += [f"**Proof of Concept:** {poc}", ""]

    threats = threat_model.get("threat_model", [])
    if threats:
        lines += ["---", "", "## STRIDE Threat Model", ""]
        for t in threats:
            sev = t.get("severity", "high")
            lines += [
                f"### {_SEVERITY_EMOJI.get(sev, '')} {t.get('threat_type', '')} — {t.get('component', '')}",
                "",
                t.get("description", ""),
                "",
                "**Mitigations:**",
            ]
            for m in t.get("mitigations", []):
                lines.append(f"- {m}")
            lines.append("")

    if semgrep:
        lines += ["---", "", "## Semgrep Findings", ""]
        for sev in severity_order:
            sev_findings = [f for f in semgrep if getattr(f, "severity", "info") == sev]
            if not sev_findings:
                continue
            lines += [
                f"### {_SEVERITY_EMOJI.get(sev, '')} {sev.capitalize()} ({len(sev_findings)})",
                "",
            ]
            for f in sev_findings:
                lines += [
                    f"#### `{f.rule_id}`",
                    f"**File:** `{f.file_path}:{f.line_start}`  ",
                    f"**Message:** {f.message}",
                ]
                if f.fix_suggestion:
                    lines.append(f"**Fix:** {f.fix_suggestion}")
                lines.append("")

    if joern:
        lines += ["---", "", "## Joern CPG Findings", ""]
        for f in joern:
            sev = getattr(f, "severity", "high")
            lines.append(
                f"- {_SEVERITY_EMOJI.get(sev, '')} **`{f.rule_id}`** | `{f.file_path}:{f.line}` | `{f.method_name}`"
            )
        lines.append("")

    if ai_segs:
        lines += [
            "---",
            "",
            "## AI-Generated Code Segments",
            "",
            "Files below contain patterns consistent with AI code generation tools.",
            "",
        ]
        for seg in ai_segs:
            lines += [
                f"### `{seg.file_path}` (confidence: {seg.confidence:.0%})",
                "",
                "**Signals:**",
            ]
            for signal in seg.signals:
                lines.append(f"- {signal}")
            lines.append("")

    return "\n".join(lines)


def generate_sarif(state: ScanState) -> dict[str, Any]:
    semgrep = state.get("semgrep_findings", [])
    joern = state.get("joern_findings", [])
    repo_url = state.get("repo_url", "")

    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}

    for f in semgrep:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("-", " ").title(),
                "shortDescription": {"text": f.message[:100]},
                "properties": {"tags": ["security", "semgrep"]},
            }
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {"startLine": f.line_start, "endLine": f.line_end},
                        }
                    }
                ],
            }
        )

    for f in joern:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("-", " ").title(),
                "shortDescription": {"text": f"CPG analysis: {f.rule_id}"},
                "properties": {"tags": ["security", "joern", "cpg"]},
            }
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f"Method: {f.method_name}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {"startLine": f.line},
                        }
                    }
                ],
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RedTeam Agent",
                        "version": "0.1.0",
                        "informationUri": "https://sarajevo.is",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "versionControlProvenance": [{"repositoryUri": repo_url}] if repo_url else [],
            }
        ],
    }
