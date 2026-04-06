"""Tests for AST analyzer."""

from vulnchain.analysis.ast_analyzer import analyze_file
from vulnchain.ingestion.models import SourceFile


def test_python_function_detection(python_source_file):
    result = analyze_file(python_source_file)
    func_names = [f.name for f in result.functions]
    assert "helper" in func_names
    assert "get_users" in func_names


def test_python_endpoint_detection(python_source_file):
    result = analyze_file(python_source_file)
    assert any(e.path == "/users" for e in result.endpoints)


def test_csharp_endpoint_detection(csharp_source_file):
    result = analyze_file(csharp_source_file)
    paths = [e.path for e in result.endpoints]
    assert "/api/users" in paths or any("/api/users" in p for p in paths)


def test_csharp_authorized_endpoint(csharp_source_file):
    result = analyze_file(csharp_source_file)
    admin_ep = next((e for e in result.endpoints if "admin" in e.path), None)
    if admin_ep:
        assert admin_ep.requires_auth is True


def test_unknown_language_returns_empty():
    sf = SourceFile(
        relative_path="script.sh",
        content="#!/bin/bash\necho hello",
        language="shell",
        size_bytes=30,
    )
    result = analyze_file(sf)
    assert result.functions == []
    assert result.endpoints == []


def test_empty_file_no_crash():
    sf = SourceFile(
        relative_path="empty.py",
        content="",
        language="python",
        size_bytes=0,
    )
    result = analyze_file(sf)
    assert result is not None
