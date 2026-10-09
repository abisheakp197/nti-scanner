"""Unit tests for the AST parser."""
from pathlib import Path
from nti_scanner.ast_analysis.parser import parse_python_file


def test_parse_valid_file(tmp_python_file):
    f = tmp_python_file("x = 1")
    tree = parse_python_file(f)
    assert tree is not None


def test_parse_invalid_syntax(tmp_python_file):
    f = tmp_python_file("def broken(")
    tree = parse_python_file(f)
    assert tree is None


def test_parse_empty_file(tmp_python_file):
    f = tmp_python_file("")
    tree = parse_python_file(f)
    assert tree is not None


def test_parse_nonexistent_file(tmp_path):
    tree = parse_python_file(tmp_path / "does_not_exist.py")
    assert tree is None


def test_parse_unicode_content(tmp_python_file):
    f = tmp_python_file('x = "héllo wörld"')
    tree = parse_python_file(f)
    assert tree is not None
