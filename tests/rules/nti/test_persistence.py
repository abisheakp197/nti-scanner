"""Tests for NTI-PERS-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.nti.persistence import PersistenceRule


def test_rule_exists_and_meta():
    r = PersistenceRule()
    assert r.meta.id == "NTI-PERS-001"


def test_vulnerable_agent_no_crash(fixtures_dir):
    rule = PersistenceRule()
    for f in (fixtures_dir / "vulnerable_agent").rglob("*.py"):
        t = parse_python_file(f)
        if t:
            rule.check(f, t, [])
