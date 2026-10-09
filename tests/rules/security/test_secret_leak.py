"""Tests for SEC-SECRET-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.secret_leak import SecretLeakRule


def test_openai_key_detected(tmp_path):
    code = 'API_KEY = "sk-1234567890abcdefghijklmnopqrstuv"\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = SecretLeakRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-SECRET-001" for x in findings)


def test_github_token_detected(tmp_path):
    code = 'TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = SecretLeakRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-SECRET-001" for x in findings)


def test_normal_string_no_finding(tmp_path):
    code = 'NAME = "hello world"\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = SecretLeakRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
