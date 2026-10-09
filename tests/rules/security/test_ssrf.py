"""Tests for SEC-SSRF-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.ssrf import SSRRule


def test_dynamic_url_detected(tmp_path):
    code = 'import requests\nurl = user_input\nrequests.get(url)\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = SSRRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-SSRF-001" for x in findings)
