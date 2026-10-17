"""Tests for SEC-PATH-001."""
from pathlib import Path

from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.path_traversal import PathTraversalRule


def test_concat_path_detected(tmp_path: Path) -> None:
    code = 'base = "/data/"\nopen(base + user_input)\n'
    f = tmp_path / "test.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = PathTraversalRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-PATH-001" for x in findings)


def test_safe_path_no_finding(tmp_path: Path) -> None:
    code = 'import os\npath = os.path.realpath("/data/file.txt")\nopen(path)\n'
    f = tmp_path / "test.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = PathTraversalRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
