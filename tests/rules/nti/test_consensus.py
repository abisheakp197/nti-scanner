"""Tests for NTI-CONS-001."""
from pathlib import Path
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.nti.consensus import ConsensusRule


def test_single_agent_no_consensus_finding(tmp_path):
    code = '''
from crewai import Agent
a = Agent(role="test")
'''
    f = tmp_path / "single.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = ConsensusRule()
    findings = rule.check(f, tree, [])
    assert not any(x.rule_id == "NTI-CONS-001" for x in findings)


def test_multi_agent_triggers_consensus(tmp_path):
    code = '''
from crewai import Agent
a = Agent(role="one")
b = Agent(role="two")
'''
    f = tmp_path / "multi.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = ConsensusRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "NTI-CONS-001" for x in findings)
