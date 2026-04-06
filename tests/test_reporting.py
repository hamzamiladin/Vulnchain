"""Tests for report formatter."""

import json
import pytest
from redteam.reporting.formatter import generate_markdown, generate_sarif
from redteam.analysis.models import SemgrepFinding, AttackChain, ThreatModel


@pytest.fixture
def scan_data(sample_semgrep_finding, sample_attack_chain):
    threat_model = ThreatModel(
        stride_categories={"injection": ["SQL injection in /users endpoint"]},
        high_risk_endpoints=["/users"],
        sensitive_data_flows=["user input → raw SQL"],
        ai_assisted_files=[],
        summary="High risk: SQL injection in unauthenticated endpoint.",
    )
    return {
        "scan_id": "test-001",
        "repo_name": "example/repo",
        "commit_sha": "abc123def456",
        "findings": [sample_semgrep_finding],
        "attack_chains": [sample_attack_chain],
        "threat_model": threat_model,
    }


def test_generate_markdown_contains_scan_id(scan_data):
    md = generate_markdown(**scan_data)
    assert "test-001" in md or "example/repo" in md


def test_generate_markdown_contains_finding(scan_data):
    md = generate_markdown(**scan_data)
    assert "SQL injection" in md or "sqli" in md.lower()


def test_generate_markdown_contains_attack_chain(scan_data):
    md = generate_markdown(**scan_data)
    assert "SQL Injection" in md or "attack" in md.lower()


def test_generate_sarif_valid_structure(scan_data):
    sarif = generate_sarif(**scan_data)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1


def test_generate_sarif_contains_results(scan_data):
    sarif = generate_sarif(**scan_data)
    results = sarif["runs"][0]["results"]
    assert len(results) >= 1


def test_generate_sarif_result_has_required_fields(scan_data):
    sarif = generate_sarif(**scan_data)
    result = sarif["runs"][0]["results"][0]
    assert "ruleId" in result
    assert "message" in result
    assert "locations" in result


def test_generate_sarif_is_json_serializable(scan_data):
    sarif = generate_sarif(**scan_data)
    serialized = json.dumps(sarif)
    assert len(serialized) > 0
