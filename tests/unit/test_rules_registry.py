"""Rules registry consistency."""
from nti_scanner.rules.registry import RULES


def test_expected_rule_count():
    assert len(RULES) >= 19


def test_all_rules_have_unique_ids():
    ids = [r.meta.id for r in RULES]
    assert len(ids) == len(set(ids))


def test_all_rules_have_cwe():
    for r in RULES:
        assert r.meta.cwe, f"{r.meta.id} missing CWE"


def test_all_rules_have_severity():
    valid = {"critical", "high", "medium", "low", "info"}
    for r in RULES:
        assert r.meta.severity in valid


def test_all_rules_have_confidence():
    valid = {"high", "medium", "low"}
    for r in RULES:
        assert r.meta.confidence in valid


def test_all_rules_have_remediation():
    for r in RULES:
        assert r.meta.remediation, f"{r.meta.id} missing remediation"
