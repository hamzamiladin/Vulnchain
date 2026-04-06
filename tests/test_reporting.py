"""Tests for report formatter."""

import json

import pytest

from vulnchain.reporting.formatter import generate_markdown, generate_sarif


@pytest.fixture
def scan_state(sample_semgrep_finding, sample_attack_chain):
    threat_model = {
        "threats": [{"category": "injection", "description": "SQL injection in /users endpoint"}],
        "high_value_targets": ["/users"],
        "attack_surface_summary": "High risk: SQL injection in unauthenticated endpoint.",
    }
    return {
        "scan_id": "test-001",
        "repo_url": "https://github.com/example/repo",
        "commit_sha": "abc123def456",
        "pr_number": None,
        "is_local": False,
        "repo_path": "",
        "source_files": [],
        "commit_history": [],
        "ast_results": [],
        "semgrep_findings": [sample_semgrep_finding],
        "joern_findings": [],
        "ai_code_segments": [],
        "dependency_findings": [],
        "tech_profile": None,
        "llm_review_findings": [],
        "threat_model": threat_model,
        "attack_chains": [sample_attack_chain],
        "report_markdown": "",
        "report_sarif": {},
        "error": None,
    }


def test_generate_markdown_contains_scan_id(scan_state):
    md = generate_markdown(scan_state)
    assert "test-001" in md or "example/repo" in md


def test_generate_markdown_contains_finding(scan_state):
    md = generate_markdown(scan_state)
    assert "SQL injection" in md or "sqli" in md.lower()


def test_generate_markdown_contains_attack_chain(scan_state):
    md = generate_markdown(scan_state)
    assert "SQL Injection" in md or "attack" in md.lower()


def test_generate_sarif_valid_structure(scan_state):
    sarif = generate_sarif(scan_state)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1


def test_generate_sarif_contains_results(scan_state):
    sarif = generate_sarif(scan_state)
    results = sarif["runs"][0]["results"]
    assert len(results) >= 1


def test_generate_sarif_result_has_required_fields(scan_state):
    sarif = generate_sarif(scan_state)
    result = sarif["runs"][0]["results"][0]
    assert "ruleId" in result
    assert "message" in result
    assert "locations" in result


def test_generate_sarif_is_json_serializable(scan_state):
    sarif = generate_sarif(scan_state)
    serialized = json.dumps(sarif)
    assert len(serialized) > 0
