"""Missing files and empty dirs."""
from pathlib import Path
from nti_scanner.scanner import scan_directory


def test_empty_directory(tmp_path):
    result = scan_directory(tmp_path)
    assert result.files_scanned == 0
    assert result.findings == []


def test_nonexistent_directory_returns_empty():
    from pathlib import Path
    result = scan_directory(Path("/tmp/does_not_exist_nti_test"))
    assert result.files_scanned == 0
