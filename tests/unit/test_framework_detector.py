"""Tests for framework detection."""
from pathlib import Path
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.framework.detector import detect_frameworks


def _trees(fixtures_dir, subdir):
    trees = {}
    for f in (fixtures_dir / subdir).rglob("*.py"):
        t = parse_python_file(f)
        if t:
            trees[f] = t
    return trees


def test_detect_langchain(fixtures_dir):
    trees = _trees(fixtures_dir, "langchain_agent")
    fw = detect_frameworks(trees)
    assert "langchain" in fw


def test_detect_in_safe_agent(fixtures_dir):
    trees = _trees(fixtures_dir, "safe_agent")
    fw = detect_frameworks(trees)
    assert "langchain" in fw


def test_no_frameworks_in_empty(tmp_python_file):
    f = tmp_python_file("x = 1")
    trees = {f: parse_python_file(f)}
    assert detect_frameworks(trees) == []
