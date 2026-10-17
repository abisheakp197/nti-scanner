"""Tests for NTI-PERS-001."""
from pathlib import Path

from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.nti.persistence import PersistenceRule


def test_rule_exists_and_meta() -> None:
    r = PersistenceRule()
    assert r.meta.id == "NTI-PERS-001"
    assert r.meta.cwe == "CWE-353"


def test_agent_without_persistence_triggers_finding(tmp_path: Path) -> None:
    code = """
from langchain.agents import Agent

agent = Agent()
"""
    f = tmp_path / "agent.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = PersistenceRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 1
    assert findings[0].rule_id == "NTI-PERS-001"


def test_agent_with_persistence_no_finding(tmp_path: Path) -> None:
    code = """
from langchain.agents import Agent

agent = Agent()
def save_state():
    # persist agent state with integrity checks
    pass
"""
    f = tmp_path / "agent.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = PersistenceRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
