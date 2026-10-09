"""Same input must always produce the same score (determinism)."""
from nti_scanner.scanner import scan_directory


def test_vulnerable_score_deterministic(vulnerable_project):
    a = scan_directory(vulnerable_project)
    b = scan_directory(vulnerable_project)
    assert a.nti1_score == b.nti1_score


def test_safe_score_deterministic(safe_project):
    a = scan_directory(safe_project)
    b = scan_directory(safe_project)
    assert a.nti1_score == b.nti1_score


def test_findings_count_deterministic(vulnerable_project):
    a = scan_directory(vulnerable_project)
    b = scan_directory(vulnerable_project)
    assert len(a.findings) == len(b.findings)


def test_frameworks_deterministic(vulnerable_project):
    a = scan_directory(vulnerable_project)
    b = scan_directory(vulnerable_project)
    assert a.frameworks == b.frameworks
