"""Tests for SEC-A2A-001."""
from pathlib import Path

from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.a2a_rules import A2ARule


def test_a2a_without_identity(tmp_path: Path) -> None:
    code = 'from a2a import A2AClient\nclient = A2AClient()\n'
    f = tmp_path / "test.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = A2ARule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-A2A-001" for x in findings)


def test_a2a_with_identity_no_finding(tmp_path: Path) -> None:
    code = 'from a2a import A2AClient\nclient = A2AClient()\nsignature = dilithium.sign("data")\n'
    f = tmp_path / "test.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = A2ARule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
