"""Tests for NTI-TRUST-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.nti.trust_boundary import TrustBoundaryRule


def test_rule_meta():
    r = TrustBoundaryRule()
    assert r.meta.id == "NTI-TRUST-001"
    assert r.meta.cwe == "CWE-1426"
