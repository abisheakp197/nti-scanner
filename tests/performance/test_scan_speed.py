"""Scan speed must be reasonable for large projects."""
import time
from nti_scanner.scanner import scan_directory


def test_scan_small_project_under_5s(safe_project):
    t0 = time.time()
    scan_directory(safe_project)
    elapsed = time.time() - t0
    assert elapsed < 5.0


def test_scan_100_files_under_10s(tmp_path):
    for i in range(100):
        (tmp_path / f"file_{i}.py").write_text(f"x_{i} = {i}\n")
    t0 = time.time()
    result = scan_directory(tmp_path)
    elapsed = time.time() - t0
    assert result.files_scanned == 100
    assert elapsed < 10.0


def test_scan_1000_files_under_30s(tmp_path):
    for i in range(1000):
        (tmp_path / f"file_{i}.py").write_text(f"x_{i} = {i}\n")
    t0 = time.time()
    result = scan_directory(tmp_path)
    elapsed = time.time() - t0
    assert result.files_scanned == 1000
    assert elapsed < 30.0
