"""Tests for NTI-PQC-001 (compliance gap, not a vulnerability tier)."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.pqc_readiness import PQCReadinessRule


def _findings(tmp_path, code):
    f = tmp_path / "test.py"
    f.write_text(code)
    return PQCReadinessRule().check(f, parse_python_file(f), [])


def test_rsa_import_detected(tmp_path):
    findings = _findings(tmp_path, "from cryptography.hazmat.primitives.asymmetric import rsa\n")
    assert any(x.rule_id == "NTI-PQC-001" for x in findings)


def test_pqc_is_a_compliance_gap_not_a_vulnerability(tmp_path):
    """Regression: importing a library is not a high-severity vulnerability."""
    findings = _findings(tmp_path, "from cryptography.hazmat.primitives.asymmetric import rsa\n")
    assert findings
    assert findings[0].category == "Compliance"
    assert findings[0].severity == "info"


def test_modern_code_no_finding(tmp_path):
    assert _findings(tmp_path, "from ube_foundation import TrustEngine\n") == []
