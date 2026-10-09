"""Full scan of the safe fixture."""
from nti_scanner.scanner import scan_directory


def test_scan_safe_returns_result(safe_project):
    result = scan_directory(safe_project)
    assert result.files_scanned >= 1


def test_scan_safe_high_score(safe_project):
    result = scan_directory(safe_project)
    # Safe agent should score higher than vulnerable
    assert result.nti1_score >= 40
