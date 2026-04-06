"""GitHub PR comment renderer for scan results."""

import logging
from dataclasses import dataclass

from vulnchain.agent.state import ScanState

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


@dataclass
class PRComment:
    title: str
    body: str
    summary_line: str


def render_pr_comment(state: ScanState) -> PRComment:
    """Render a GitHub PR comment from scan results."""
    semgrep = state.get("semgrep_findings", [])
    joern = state.get("joern_findings", [])
    ai_segs = state.get("ai_code_segments", [])
    attack_chains = state.get("attack_chains", [])

    all_findings = [
        {
            "severity": f.severity,
            "rule_id": f.rule_id,
            "file": f.file_path,
            "line": f.line_start,
            "message": f.message,
        }
        for f in semgrep
    ] + [
        {
            "severity": f.severity,
            "rule_id": f.rule_id,
            "file": f.file_path,
            "line": f.line,
            "message": f"CPG: {f.method_name}",
        }
        for f in joern
    ]

    severity_order = ["critical", "high", "medium", "low", "info"]
    counts = dict.fromkeys(severity_order, 0)
    for f in all_findings:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1

    total = sum(counts.values())
    critical_high = counts["critical"] + counts["high"]

    lines = [
        "## 🔍 RedTeam Security Scan Results",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for sev in severity_order:
        if counts[sev] > 0:
            lines.append(f"| {_SEVERITY_EMOJI.get(sev, '')} {sev.capitalize()} | {counts[sev]} |")

    lines += ["", f"**Total findings:** {total}", ""]

    top = [f for f in all_findings if f["severity"] in ("critical", "high")][:5]
    if top:
        lines += ["### 🚨 Critical / High Findings", ""]
        for f in top:
            lines.append(
                f"- {_SEVERITY_EMOJI.get(f['severity'], '')} **`{f['rule_id']}`** — "
                f"`{f['file']}:{f['line']}` — {f['message'][:120]}"
            )
        lines.append("")

    if attack_chains:
        lines += ["### ⛓️ Attack Chains", ""]
        for chain in attack_chains[:3]:
            sev = getattr(chain, "combined_severity", "high")
            lines.append(f"#### {_SEVERITY_EMOJI.get(sev, '🟠')} {chain.title}")
            for step in chain.steps:
                lines.append(f"1. {step}")
            lines += ["", f"> **Business impact:** {chain.business_impact}", ""]

    if ai_segs:
        lines += [
            "### 🤖 AI-Generated Code Detected",
            "",
            f"{len(ai_segs)} file(s) contain likely AI-generated code segments.",
            "",
        ]

    if critical_high == 0:
        summary = f"✅ {total} findings (no critical/high)"
    else:
        summary = f"❌ {critical_high} critical/high findings out of {total} total"

    return PRComment(
        title=f"RedTeam Scan: {summary}",
        body="\n".join(lines),
        summary_line=summary,
    )
