"""Tests for NTI-CAPDIFF-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.nti.capability_diff import CapabilityDiffRule


def _check(fixtures_dir, subdir):
    rule = CapabilityDiffRule()
    findings = []
    for f in (fixtures_dir / subdir).rglob("*.py"):
        t = parse_python_file(f)
        if t:
            findings.extend(rule.check(f, t, []))
    return findings


def test_mixed_agent_triggers_capability_diff(fixtures_dir):
    findings = _check(fixtures_dir, "mixed_agent")
    assert any(f.rule_id == "NTI-CAPDIFF-001" for f in findings)


def test_vulnerable_agent_triggers_capability_diff(fixtures_dir):
    findings = _check(fixtures_dir, "vulnerable_agent")
    assert any(f.rule_id == "NTI-CAPDIFF-001" for f in findings)
