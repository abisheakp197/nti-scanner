"""Tests for SEC-SQL-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.sql_injection import SQLInjectionRule


def _findings(tmp_path, code, name="mod.py"):
    f = tmp_path / name
    f.write_text(code)
    tree = parse_python_file(f)
    return SQLInjectionRule().check(f, tree, [])


def test_interpolated_query_executed(tmp_path):
    code = (
        'user = "admin"\n'
        'q = f"SELECT * FROM users WHERE name={user}"\n'
        'cursor.execute(q)\n'
    )
    assert any(x.rule_id == "SEC-SQL-001" for x in _findings(tmp_path, code))


def test_parameterized_query_no_finding(tmp_path):
    code = 'query = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (1,))\n'
    assert _findings(tmp_path, code) == []


def test_fstring_with_sql_word_not_executed_is_not_a_finding(tmp_path):
    """Regression: prose like 'copied from X' used to be a critical finding."""
    code = 'origin = "copied from the upstream README"\nprint(f"Source: {origin}")\n'
    assert _findings(tmp_path, code) == []
