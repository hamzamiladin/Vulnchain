"""Tests for AI-generated code detector."""

import pytest
from redteam.analysis.ai_code_detector import (
    detect_ai_code,
    _score_commit_signals,
    _score_code_patterns,
    _score_method_validity,
    _score_security_antipatterns,
    _score_comment_density,
    _score_placeholder_strings,
    MIN_CONFIDENCE,
)
from redteam.ingestion.models import SourceFile, CommitInfo


# ── commit signal tests ───────────────────────────────────────────────────────

def test_ai_commit_signal_raises_score(python_source_file, ai_commit):
    score, signals = _score_commit_signals(python_source_file.relative_path, [ai_commit])
    assert score > 0
    assert any("AI tool attribution" in s for s in signals)


def test_normal_commit_no_signal(python_source_file, normal_commit):
    score, signals = _score_commit_signals(python_source_file.relative_path, [normal_commit])
    assert score == 0.0


def test_large_atomic_addition_raises_score():
    commit = CommitInfo(
        sha="abc123",
        message="feat: add user service",
        author="dev@example.com",
        timestamp="2024-01-15T10:00:00Z",
        files_changed=["services/user.py"],
        additions=200,
        deletions=0,
    )
    score, signals = _score_commit_signals("services/user.py", [commit])
    assert score > 0
    assert any("dump" in s.lower() or "atomic" in s.lower() for s in signals)


def test_cursor_attribution_detected():
    commit = CommitInfo(
        sha="def456",
        message="Co-authored-by: Cursor <cursor@anysphere.inc>",
        author="dev@example.com",
        timestamp="2024-01-15T10:00:00Z",
        files_changed=["app.py"],
        additions=30,
        deletions=5,
    )
    score, signals = _score_commit_signals("app.py", [commit])
    assert score > 0


# ── code pattern tests ────────────────────────────────────────────────────────

def test_todo_placeholder_detected():
    content = "# TODO: add error handling\ndef foo(): pass"
    score, signals = _score_code_patterns(content, "x.py")
    assert score > 0
    assert any("TODO" in s for s in signals)


def test_broad_catch_detected():
    content = "try:\n    pass\nexcept Exception as e:\n    pass\n"
    score, signals = _score_code_patterns(content, "x.py")
    assert score > 0
    assert any("broad exception" in s.lower() or "catch" in s.lower() for s in signals)


def test_over_comment_detected():
    content = (
        "# This function validates the user input\n"
        "# This method returns the processed result\n"
        "# This code handles the error case\n"
        "def foo(x): return x\n"
    )
    score, signals = _score_code_patterns(content, "x.py")
    assert score > 0
    assert any("over-explanatory" in s.lower() or "comment" in s.lower() for s in signals)


# ── security antipattern tests ────────────────────────────────────────────────

def test_ssl_verify_false_detected():
    content = "resp = requests.get(url, verify=False)\n"
    score, signals = _score_security_antipatterns(content)
    assert score > 0
    assert any("SSL" in s or "verify" in s.lower() for s in signals)


def test_placeholder_secret_detected():
    content = 'SECRET_KEY = "your-secret-key"\napi_key = "changeme"\n'
    score, signals = _score_security_antipatterns(content)
    assert score > 0
    assert any("placeholder" in s.lower() or "credential" in s.lower() for s in signals)


def test_weak_password_hash_detected():
    content = "hashed = hashlib.sha256(password.encode()).hexdigest()\n"
    score, signals = _score_security_antipatterns(content)
    assert score > 0
    assert any("password" in s.lower() or "hash" in s.lower() for s in signals)


def test_jwt_no_verify_detected():
    content = 'data = jwt.decode(token, options={"verify_signature": False})\n'
    score, signals = _score_security_antipatterns(content)
    assert score > 0
    assert any("JWT" in s or "signature" in s.lower() for s in signals)


def test_insecure_skip_verify_tls():
    content = "cfg = tls.Config{InsecureSkipVerify: true}\n"
    score, signals = _score_security_antipatterns(content)
    assert score > 0


def test_no_antipatterns_clean_code():
    content = (
        "import bcrypt\n"
        "hashed = bcrypt.hashpw(password, bcrypt.gensalt())\n"
        "resp = requests.get(url, verify=True)\n"
    )
    score, signals = _score_security_antipatterns(content)
    assert score == 0.0
    assert signals == []


# ── comment density tests ─────────────────────────────────────────────────────

def test_high_comment_density_detected():
    # 10 comment lines, 5 code lines = 66% — very high
    content = "\n".join(
        ["# This is a comment describing line"] * 10 + ["x = 1", "y = 2", "z = 3", "w = 4", "v = 5"]
    )
    score, signals = _score_comment_density(content, "python")
    assert score > 0
    assert any("comment" in s.lower() or "density" in s.lower() for s in signals)


def test_normal_comment_density_no_flag():
    # 2 comments, 20 code lines = 9% — normal
    content = "\n".join(
        ["# Setup", "x = 1"] + ["y = %d" % i for i in range(20)]
    )
    score, signals = _score_comment_density(content, "python")
    assert score == 0.0


def test_comment_density_short_file_skipped():
    content = "# comment\nx = 1\n"
    score, signals = _score_comment_density(content, "python")
    assert score == 0.0  # too short to score


def test_unsupported_language_skipped():
    content = "-- SQL comment\nSELECT * FROM foo;\n"
    score, signals = _score_comment_density(content, "sql")
    assert score == 0.0


# ── placeholder string tests ──────────────────────────────────────────────────

def test_placeholder_strings_detected():
    content = (
        'BASE_URL = "example.com"\n'
        'host = "localhost"\n'
        'db = "dummy_data"\n'
        'user = "foo"\n'
    )
    score, signals = _score_placeholder_strings(content)
    assert score > 0
    assert any("placeholder" in s.lower() for s in signals)


def test_real_values_not_flagged():
    content = (
        'BASE_URL = "api.myservice.com"\n'
        'TIMEOUT = 30\n'
        'MAX_RETRIES = 3\n'
    )
    score, signals = _score_placeholder_strings(content)
    assert score == 0.0


# ── method validity tests ─────────────────────────────────────────────────────

def test_phantom_methods_raise_validity_score():
    content = """\
def myFunc():
    result = obj.phantomMethod1()
    result = obj.phantomMethod2()
    result = obj.phantomMethod3()
    result = obj.phantomMethod4()
    result = obj.phantomMethod5()
    result = obj.phantomMethod6()
    return result
"""
    score, signals = _score_method_validity(content, "python")
    assert score > 0


def test_no_phantom_methods_clean():
    content = """\
def process(items):
    result = []
    for item in items:
        result.append(item.strip())
    return result
"""
    score, signals = _score_method_validity(content, "python")
    # Should not flag standard library methods
    assert score == 0.0


# ── integration tests ─────────────────────────────────────────────────────────

def test_detect_ai_code_returns_high_confidence_file(python_source_file, ai_commit):
    segments = detect_ai_code([python_source_file], [ai_commit])
    assert len(segments) >= 1
    assert segments[0].file_path == python_source_file.relative_path
    assert segments[0].confidence >= MIN_CONFIDENCE


def test_detect_ai_code_sorted_descending():
    files = [
        SourceFile(relative_path="a.py", content="x = 1", language="python", size_bytes=5),
        SourceFile(
            relative_path="b.py",
            content=(
                "# TODO: add error handling\n"
                "# TODO: implement this\n"
                "resp = requests.get(url, verify=False)\n"
                'SECRET = "your-secret-key"\n'
            ) * 3,
            language="python",
            size_bytes=400,
        ),
    ]
    segments = detect_ai_code(files, [])
    if len(segments) >= 2:
        assert segments[0].confidence >= segments[1].confidence


def test_detect_ai_code_high_confidence_with_antipatterns():
    """File with multiple AI signals should hit high confidence."""
    content = (
        "# This function validates the user authentication token\n"
        "# This method returns the processed response data\n"
        "# This code handles all the error cases\n"
        "# Note that this is a placeholder implementation\n"
        "import requests\n"
        "import hashlib\n"
        "\n"
        "# TODO: add error handling\n"
        "# TODO: implement proper validation\n"
        "\n"
        'SECRET_KEY = "your-secret-key"\n'
        'API_KEY = "changeme"\n'
        "\n"
        "def authenticate(password):\n"
        "    # This function hashes the password using SHA256\n"
        "    hashed = hashlib.sha256(password.encode()).hexdigest()\n"
        "    return hashed\n"
        "\n"
        "def fetch_data(url):\n"
        "    # This method fetches data from the given URL\n"
        "    resp = requests.get(url, verify=False)\n"
        "    return resp.json()\n"
    )
    sf = SourceFile(
        relative_path="auth.py",
        content=content,
        language="python",
        size_bytes=len(content),
    )
    segments = detect_ai_code([sf], [])
    assert len(segments) == 1
    assert segments[0].confidence >= 0.55  # Should be clearly flagged


def test_clean_file_not_flagged():
    """Well-written human code without AI signals should not be flagged."""
    content = (
        "import secrets\n"
        "import bcrypt\n"
        "\n"
        "def authenticate(password: str, stored_hash: bytes) -> bool:\n"
        "    return bcrypt.checkpw(password.encode(), stored_hash)\n"
        "\n"
        "def generate_token() -> str:\n"
        "    return secrets.token_urlsafe(32)\n"
    )
    sf = SourceFile(
        relative_path="auth.py",
        content=content,
        language="python",
        size_bytes=len(content),
    )
    segments = detect_ai_code([sf], [])
    assert len(segments) == 0
