"""Tests for SEC-PATH-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.path_traversal import PathTraversalRule


def test_concat_path_detected(tmp_path):
    code = 'base = "/data"\nopen(base + user_input)\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = PathTraversalRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-PATH-001" for x in findings)
