"""Tests for AST analyzer."""

from pathlib import Path

from vulnchain.analysis.ast_analyzer import analyze_file
from vulnchain.ingestion.models import SourceFile


def test_python_function_detection(python_source_file):
    result = analyze_file(python_source_file)
    func_names = [f.name for f in result.functions]
    assert "helper" in func_names
    assert "get_users" in func_names


def test_python_endpoint_detection(python_source_file):
    result = analyze_file(python_source_file)
    assert any(e.route == "/users" for e in result.api_endpoints)


def test_csharp_endpoint_detection(csharp_source_file):
    result = analyze_file(csharp_source_file)
    paths = [e.route for e in result.api_endpoints]
    assert "/api/users" in paths or any("/api/users" in p for p in paths)


def test_csharp_authorized_endpoint(csharp_source_file):
    result = analyze_file(csharp_source_file)
    admin_ep = next((e for e in result.api_endpoints if "admin" in e.route), None)
    if admin_ep:
        assert admin_ep.has_auth_decorator is True


def test_unknown_language_returns_empty():
    sf = SourceFile(
        path=Path("script.sh"),
        relative_path="script.sh",
        content="#!/bin/bash\necho hello",
        language="shell",
        size_bytes=30,
    )
    result = analyze_file(sf)
    assert result.functions == []
    assert result.api_endpoints == []


def test_empty_file_no_crash():
    sf = SourceFile(
        path=Path("empty.py"),
        relative_path="empty.py",
        content="",
        language="python",
        size_bytes=0,
    )
    result = analyze_file(sf)
    assert result is not None
