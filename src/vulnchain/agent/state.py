"""LangGraph state definition for the RedTeam scan pipeline."""

from typing import TypedDict


class ScanState(TypedDict):
    # Input
    repo_url: str
    pr_number: int | None
    commit_sha: str | None
    scan_id: str
    is_local: bool

    # Ingestion
    repo_path: str
    source_files: list
    commit_history: list

    # Analysis
    ast_results: list
    semgrep_findings: list
    ai_code_segments: list
    joern_findings: list
    dependency_findings: list  # CVEs from OSV API
    tech_profile: dict | None  # detected frameworks/versions

    # LLM reasoning
    llm_review_findings: list
    threat_model: dict | None
    attack_chains: list

    # Output
    report_markdown: str
    report_sarif: dict
    error: str | None
