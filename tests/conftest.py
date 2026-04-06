"""Shared pytest fixtures."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from vulnchain.ingestion.models import SourceFile, CommitInfo
from vulnchain.analysis.models import (
    SemgrepFinding,
    JoernFinding,
    AICodeSegment,
    ThreatModel,
    AttackChain,
)


@pytest.fixture
def python_source_file():
    return SourceFile(
        relative_path="app/routes.py",
        content='''\
from flask import Flask, request
app = Flask(__name__)

def helper():
    pass

@app.route("/users")
def get_users():
    query = "SELECT * FROM users WHERE id=" + request.args.get("id", "")
    # TODO: add error handling
    result = db.execute(query)
    return result
''',
        language="python",
        size_bytes=300,
    )


@pytest.fixture
def csharp_source_file():
    return SourceFile(
        relative_path="Controllers/UserController.cs",
        content='''\
[HttpGet("/api/users")]
public IActionResult GetUsers(string id) {
    var query = "SELECT * FROM Users WHERE Id=" + id;
    return Ok(_db.Execute(query));
}

[HttpPost("/api/admin")]
[Authorize]
public IActionResult Admin() { return Ok(); }
''',
        language="csharp",
        size_bytes=250,
    )


@pytest.fixture
def ai_commit():
    return CommitInfo(
        sha="abc12345def67890",
        message="Co-authored-by: GitHub Copilot <copilot@github.com>",
        author="dev@example.com",
        timestamp="2024-01-15T10:00:00Z",
        files_changed=["app/routes.py"],
        additions=120,
        deletions=5,
    )


@pytest.fixture
def normal_commit():
    return CommitInfo(
        sha="111222333444555",
        message="fix: correct typo in variable name",
        author="dev@example.com",
        timestamp="2024-01-16T10:00:00Z",
        files_changed=["app/routes.py"],
        additions=2,
        deletions=2,
    )


@pytest.fixture
def sample_semgrep_finding():
    return SemgrepFinding(
        rule_id="python.lang.security.sqli",
        severity="critical",
        file_path="app/routes.py",
        line_start=10,
        line_end=10,
        message="SQL injection via string concatenation",
        fix_suggestion="Use parameterized queries",
        raw={},
    )


@pytest.fixture
def sample_joern_finding():
    return JoernFinding(
        rule_id="missing-authorization",
        severity="high",
        file_path="Controllers/UserController.cs",
        line=5,
        method_name="GetUsers",
        script="missing_auth.sc",
        raw={},
    )


@pytest.fixture
def sample_attack_chain():
    return AttackChain(
        title="SQL Injection → Data Exfiltration",
        severity="critical",
        description="Attacker exploits SQLi to dump user table.",
        steps=["Send crafted GET /users?id=1 OR 1=1", "Execute raw SQL", "Exfiltrate data"],
        finding_ids=["finding-1", "finding-2"],
        likelihood=4,
        impact=5,
        cvss_score=9.1,
    )
