"""LangGraph state definition for the Vulnchain scan pipeline."""

from typing import Any, TypedDict


class ScanState(TypedDict):
    # Input
    repo_url: str
    pr_number: int | None
    commit_sha: str | None
    scan_id: str
    is_local: bool

    # Ingestion
    repo_path: str
    source_files: list[Any]
    commit_history: list[Any]

    # Analysis
    ast_results: list[Any]
    semgrep_findings: list[Any]
    ai_code_segments: list[Any]
    joern_findings: list[Any]
    dependency_findings: list[Any]  # CVEs from OSV API
    tech_profile: dict[str, Any] | None  # detected frameworks/versions

    # LLM reasoning
    llm_review_findings: list[Any]
    threat_model: dict[str, Any] | None
    attack_chains: list[Any]

    # Output
    report_markdown: str
    report_sarif: dict[str, Any]
    error: str | None
