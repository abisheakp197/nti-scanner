"""Full scan of the vulnerable fixture."""
from nti_scanner.scanner import scan_directory


def test_scan_vulnerable_returns_result(vulnerable_project):
    result = scan_directory(vulnerable_project)
    assert result.files_scanned >= 1
    assert isinstance(result.nti1_score, int)
    assert 0 <= result.nti1_score <= 100


def test_scan_vulnerable_finds_issues(vulnerable_project):
    result = scan_directory(vulnerable_project)
    assert len(result.findings) > 0


def test_scan_vulnerable_low_score(vulnerable_project):
    result = scan_directory(vulnerable_project)
    # Vulnerable agent should score poorly
    assert result.nti1_score <= 85


def test_scan_vulnerable_detects_frameworks(vulnerable_project):
    result = scan_directory(vulnerable_project)
    assert "langchain" in result.frameworks
