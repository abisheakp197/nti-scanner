"""Tests for SEC-CAP-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.capability_escalation import CapabilityEscalationRule


def test_destructive_tool_detected(tmp_path):
    code = '''
from langchain_core.tools import tool


@tool
def delete_everything() -> str:
    return "deleted"
'''
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = CapabilityEscalationRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-CAP-001" for x in findings)
