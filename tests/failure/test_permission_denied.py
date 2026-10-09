"""Permission denied must not crash."""
import os
import stat
from nti_scanner.scanner import scan_directory


def test_unreadable_file_skipped(tmp_path):
    f = tmp_path / "unreadable.py"
    f.write_text("x = 1")
    os.chmod(f, 0o000)
    try:
        result = scan_directory(tmp_path)
        # Must not raise
        assert isinstance(result.files_scanned, int)
    finally:
        os.chmod(f, 0o644)
