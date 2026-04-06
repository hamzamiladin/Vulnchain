"""Tests for Semgrep scanner wrapper."""

import json
import subprocess
import pytest
from unittest.mock import MagicMock, patch

from vulnchain.analysis.semgrep_scanner import run_semgrep, _parse_semgrep_finding


def _make_result(check_id, severity, path, line_start, line_end, message):
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line_start},
        "end": {"line": line_end},
        "extra": {
            "severity": severity,
            "message": message,
            "metadata": {},
        },
    }


def test_parse_semgrep_finding_critical():
    raw = _make_result("sqli-rule", "ERROR", "app/routes.py", 10, 10, "SQL injection")
    finding = _parse_semgrep_finding(raw)
    assert finding.severity == "critical"
    assert finding.rule_id == "sqli-rule"
    assert finding.file_path == "app/routes.py"
    assert finding.line_start == 10


def test_parse_semgrep_finding_warning_mapped_to_high():
    raw = _make_result("xss-rule", "WARNING", "app/views.py", 5, 7, "XSS risk")
    finding = _parse_semgrep_finding(raw)
    assert finding.severity == "high"


def test_parse_semgrep_finding_fix_suggestion():
    raw = _make_result("rule", "INFO", "a.py", 1, 1, "msg")
    raw["extra"]["metadata"]["fix"] = "Use parameterized queries"
    finding = _parse_semgrep_finding(raw)
    assert finding.fix_suggestion == "Use parameterized queries"


@patch("vulnchain.analysis.semgrep_scanner.subprocess.run")
def test_run_semgrep_returns_findings(mock_run):
    payload = {"results": [_make_result("r1", "ERROR", "f.py", 1, 1, "msg")]}
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout=json.dumps(payload),
        stderr="",
    )
    findings = run_semgrep("/fake/repo")
    assert len(findings) == 1
    assert findings[0].rule_id == "r1"


@patch("vulnchain.analysis.semgrep_scanner.subprocess.run")
def test_run_semgrep_no_findings(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps({"results": []}), stderr="")
    findings = run_semgrep("/fake/repo")
    assert findings == []


@patch("vulnchain.analysis.semgrep_scanner.subprocess.run", side_effect=FileNotFoundError)
def test_run_semgrep_not_installed(mock_run):
    findings = run_semgrep("/fake/repo")
    assert findings == []


@patch("vulnchain.analysis.semgrep_scanner.subprocess.run")
def test_run_semgrep_returns_empty_on_bad_exit(mock_run):
    # Exit code 2+ means Semgrep error — pipeline should degrade gracefully, not crash
    mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="fatal error")
    findings = run_semgrep("/fake/repo")
    assert findings == []
