"""Tests for NTI-AUDIT-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.nti.audit import AuditRule


def _check(fixtures_dir, subdir):
    rule = AuditRule()
    findings = []
    for f in (fixtures_dir / subdir).rglob("*.py"):
        t = parse_python_file(f)
        if t:
            findings.extend(rule.check(f, t, []))
    return findings


def test_vulnerable_agent_triggers_audit(fixtures_dir):
    findings = _check(fixtures_dir, "vulnerable_agent")
    assert any(f.rule_id == "NTI-AUDIT-001" for f in findings)


def test_safe_agent_no_audit_finding(fixtures_dir):
    findings = _check(fixtures_dir, "safe_agent")
    assert not any(f.rule_id == "NTI-AUDIT-001" for f in findings)
