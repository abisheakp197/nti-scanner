"""Mixed agent has partial safety."""
from nti_scanner.scanner import scan_directory


def test_scan_mixed_returns_result(mixed_project):
    result = scan_directory(mixed_project)
    assert result.files_scanned >= 1


def test_mixed_score_between_safe_and_vulnerable(mixed_project, vulnerable_project, safe_project):
    mixed = scan_directory(mixed_project)
    vuln = scan_directory(vulnerable_project)
    safe = scan_directory(safe_project)
    # Mixed should be somewhere between
    assert vuln.nti1_score <= mixed.nti1_score <= safe.nti1_score + 30
