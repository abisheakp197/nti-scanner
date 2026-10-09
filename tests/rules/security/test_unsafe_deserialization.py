"""Tests for SEC-DESER-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.unsafe_deserialization import UnsafeDeserializationRule


def test_pickle_loads_detected(tmp_path):
    code = 'import pickle\npickle.loads(data)\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = UnsafeDeserializationRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-DESER-001" for x in findings)


def test_yaml_load_detected(tmp_path):
    code = 'import yaml\nyaml.load(data)\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = UnsafeDeserializationRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-DESER-001" for x in findings)


def test_safe_json_no_finding(tmp_path):
    code = 'import json\njson.loads(data)\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = UnsafeDeserializationRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
