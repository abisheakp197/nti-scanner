"""Tests for NTI-TRUST-001."""
from pathlib import Path

from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.nti.trust_boundary import TrustBoundaryRule


def test_rule_meta() -> None:
    r = TrustBoundaryRule()
    assert r.meta.id == "NTI-TRUST-001"
    assert r.meta.cwe == "CWE-1426"


def test_trust_boundary_crossing_triggers_finding(tmp_path: Path) -> None:
    code = """
output = agent.invoke("test")
eval(output)
"""
    f = tmp_path / "boundary.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = TrustBoundaryRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 1
    assert findings[0].rule_id == "NTI-TRUST-001"


def test_safe_llm_call_without_privileged_sink_no_finding(tmp_path: Path) -> None:
    code = """
output = agent.invoke("test")
print(output)
"""
    f = tmp_path / "safe_boundary.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = TrustBoundaryRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
