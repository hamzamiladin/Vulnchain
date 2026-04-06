"""LangGraph state definition for the RedTeam scan pipeline."""

from typing import Optional, TypedDict


class ScanState(TypedDict):
    # Input
    repo_url: str
    pr_number: Optional[int]
    commit_sha: Optional[str]
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
    dependency_findings: list    # CVEs from OSV API
    tech_profile: Optional[dict] # detected frameworks/versions

    # LLM reasoning
    llm_review_findings: list
    threat_model: Optional[dict]
    attack_chains: list

    # Output
    report_markdown: str
    report_sarif: dict
    error: Optional[str]
