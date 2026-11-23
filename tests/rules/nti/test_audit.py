"""Tests for NTI-AUDIT-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.nti.audit import AuditRule


def _findings(tmp_path, code):
    f = tmp_path / "mod.py"
    f.write_text(code)
    return AuditRule().check(f, parse_python_file(f), [])


def test_agent_without_audit_trail_reported(tmp_path):
    code = 'from agent import Agent\nworker = Agent(name="w")\n'
    findings = _findings(tmp_path, code)
    assert any(x.rule_id == "NTI-AUDIT-001" for x in findings)
    assert findings[0].severity == "info"
    assert "ube-foundation" not in findings[0].remediation.lower()


def test_agent_with_audit_trail_not_reported(tmp_path):
    code = (
        'from agent import Agent\n'
        'from audit import log_event\n'
        'worker = Agent(name="w")\n'
        'log_event("agent.created", worker)\n'
    )
    assert _findings(tmp_path, code) == []
