"""Tests for LangGraph agent graph."""

from unittest.mock import patch

import pytest

from vulnchain.agent.graph import build_graph
from vulnchain.agent.state import ScanState


@pytest.fixture
def minimal_state() -> ScanState:
    return ScanState(
        scan_id="test-scan-001",
        repo_url="https://github.com/example/repo",
        commit_sha="abc123",
        pr_number=None,
        is_local=False,
        repo_path="",
        source_files=[],
        commit_history=[],
        ast_results=[],
        semgrep_findings=[],
        joern_findings=[],
        ai_code_segments=[],
        dependency_findings=[],
        tech_profile=None,
        llm_review_findings=[],
        threat_model=None,
        attack_chains=[],
        report_markdown="",
        report_sarif={},
        error=None,
    )


def test_build_graph_compiles():
    """Graph should compile without errors."""
    graph = build_graph()
    assert graph is not None


def test_state_has_required_keys(minimal_state):
    required = [
        "scan_id",
        "repo_url",
        "commit_sha",
        "source_files",
        "semgrep_findings",
        "joern_findings",
        "ai_code_segments",
        "attack_chains",
        "report_markdown",
        "report_sarif",
    ]
    for key in required:
        assert key in minimal_state, f"Missing key: {key}"


def test_state_error_initially_none(minimal_state):
    assert minimal_state["error"] is None


@patch("vulnchain.agent.nodes.clone_repo")
@patch("vulnchain.agent.nodes.collect_source_files")
@patch("vulnchain.agent.nodes.collect_commit_history")
def test_clone_repo_node_sets_source_files(mock_commits, mock_files, mock_clone, minimal_state):
    from vulnchain.agent.nodes import clone_repo_node

    mock_clone.return_value = "/tmp/fake-repo"
    mock_files.return_value = []
    mock_commits.return_value = []

    result = clone_repo_node(minimal_state)
    assert "source_files" in result
    assert "commit_history" in result
