"""Tests for SEC-PQC-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.pqc_readiness import PQCReadinessRule


def test_rsa_import_detected(tmp_path):
    code = 'from cryptography.hazmat.primitives.asymmetric import rsa\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = PQCReadinessRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-PQC-001" for x in findings)


def test_modern_code_no_finding(tmp_path):
    code = 'from ube_foundation import TrustEngine\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = PQCReadinessRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
