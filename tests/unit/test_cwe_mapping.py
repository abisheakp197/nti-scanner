"""CWE mapping tests."""
from nti_scanner.cwe.mapping import CWE_NAMES, cwe_url


def test_cwe_map_contains_expected_keys():
    for key in ["CWE-78", "CWE-89", "CWE-502", "CWE-798", "CWE-918"]:
        assert key in CWE_NAMES


def test_cwe_url_generation():
    url = cwe_url("CWE-78")
    assert "78" in url
    assert "cwe.mitre.org" in url
