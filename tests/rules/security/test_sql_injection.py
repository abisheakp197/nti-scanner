"""Tests for SEC-SQL-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.sql_injection import SQLInjectionRule


def test_fstring_sql_detected(tmp_path):
    code = 'user = "admin"\nq = f"SELECT * FROM users WHERE name={user}"\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = SQLInjectionRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-SQL-001" for x in findings)


def test_parameterized_query_no_finding(tmp_path):
    code = 'query = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (1,))\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = SQLInjectionRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
