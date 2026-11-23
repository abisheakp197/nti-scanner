"""Tests for NTI-GOV-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.nti.governance import GovernanceRule


def _findings(tmp_path, code):
    f = tmp_path / "mod.py"
    f.write_text(code)
    return GovernanceRule().check(f, parse_python_file(f), [])


def test_tools_without_capability_check_reported(tmp_path):
    code = (
        'from crewai import tool\n'
        '@tool\n'
        'def read_file(path):\n'
        '    return open(path).read()\n'
    )
    findings = _findings(tmp_path, code)
    assert any(x.rule_id == "NTI-GOV-001" for x in findings)
    assert findings[0].category == "Compliance"
    assert findings[0].severity == "info"


def test_tools_with_capability_check_not_reported(tmp_path):
    code = (
        'from crewai import tool\n'
        '@tool\n'
        'def read_file(path):\n'
        '    check_capability("fs.read")\n'
        '    return open(path).read()\n'
    )
    assert _findings(tmp_path, code) == []


def test_mentioning_nti_is_not_governance(tmp_path):
    """Regression: the word "nti" used to suppress the finding entirely."""
    code = (
        'from crewai import tool\n'
        '@tool\n'
        'def read_file(path):\n'
        '    return open(path).read()\n'
    )
    assert _findings(tmp_path, code), "a comment mentioning NTI must not mask the gap"
