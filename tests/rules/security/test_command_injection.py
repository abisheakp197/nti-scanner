"""Tests for SEC-CMD-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.command_injection import CommandInjectionRule


def test_os_system_detected(tmp_path):
    code = 'import os\nos.system("ls")\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = CommandInjectionRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-CMD-001" for x in findings)


def test_subprocess_shell_true_detected(tmp_path):
    code = 'import subprocess\nsubprocess.run("ls", shell=True)\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = CommandInjectionRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-CMD-001" for x in findings)


def test_safe_subprocess_no_finding(tmp_path):
    code = 'import subprocess\nsubprocess.run(["ls", "-la"])\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = CommandInjectionRule()
    findings = rule.check(f, tree, [])
    assert not any(x.severity == "critical" for x in findings)
