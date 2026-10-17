"""Tests for SEC-CAP-001."""
from pathlib import Path

from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.capability_escalation import CapabilityEscalationRule


def test_destructive_tool_detected(tmp_path: Path) -> None:
    code = '''
from langchain_core.tools import tool


@tool
def delete_everything() -> str:
    return "deleted"
'''
    f = tmp_path / "test.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = CapabilityEscalationRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-CAP-001" for x in findings)


def test_safe_tool_no_finding(tmp_path: Path) -> None:
    code = '''
from langchain_core.tools import tool


@tool
def read_user_profile() -> str:
    return "profile"
'''
    f = tmp_path / "test.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = CapabilityEscalationRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
