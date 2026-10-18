"""Tests for SEC-SSRF-001."""
from pathlib import Path

from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.ssrf import SSRRule


def test_dynamic_url_detected(tmp_path: Path) -> None:
    code = 'import requests\nurl = user_input\nrequests.get(url)\n'
    f = tmp_path / "test.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = SSRRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-SSRF-001" for x in findings)


def test_literal_url_no_finding(tmp_path: Path) -> None:
    code = 'import requests\nrequests.get("https://api.example.com/data")\n'
    f = tmp_path / "test.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = SSRRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
