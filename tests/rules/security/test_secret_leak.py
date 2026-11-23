"""Tests for SEC-SECRET-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.secret_leak import SecretLeakRule


def _findings(tmp_path, code, name="mod.py"):
    f = tmp_path / name
    f.write_text(code)
    return SecretLeakRule().check(f, parse_python_file(f), [])


def test_real_looking_key_detected(tmp_path):
    code = 'KEY = "sk-proj-9fK2mQ7xR4tY8vB3nJ6hL1pZ5wC0dS"\n'
    assert _findings(tmp_path, code)


def test_placeholder_key_not_detected(tmp_path):
    """Regression: 'sk-very-secret-value' was reported as critical."""
    code = 'KEY = "sk-very-secret-value"\n'
    assert _findings(tmp_path, code) == []


def test_test_fixture_not_detected(tmp_path):
    code = 'KEY = "sk-test-live-server-12345"\n'
    assert _findings(tmp_path, code, "test_remote.py") == []
