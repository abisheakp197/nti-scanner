"""Tests for NTI-IDENT-001."""
from pathlib import Path
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.nti.identity import IdentityRule


def _check(fixtures_dir, subdir):
    rule = IdentityRule()
    findings = []
    for f in (fixtures_dir / subdir).rglob("*.py"):
        t = parse_python_file(f)
        if t:
            findings.extend(rule.check(f, t, []))
    return findings


def test_vulnerable_agent_triggers_identity(fixtures_dir):
    findings = _check(fixtures_dir, "vulnerable_agent")
    assert any(f.rule_id == "NTI-IDENT-001" for f in findings)


def test_safe_agent_does_not_trigger(fixtures_dir):
    findings = _check(fixtures_dir, "safe_agent")
    assert not any(f.rule_id == "NTI-IDENT-001" for f in findings)
