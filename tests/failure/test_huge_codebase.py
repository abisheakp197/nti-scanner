"""Failure mode test for huge codebase and oversized files."""
from pathlib import Path

from nti_scanner.scanner import scan_directory


def test_huge_codebase_handled(tmp_path: Path) -> None:
    nested = tmp_path
    for d in range(10):
        nested = nested / f"dir_{d}"
        nested.mkdir()
        for i in range(5):
            (nested / f"file_{i}.py").write_text(f"x_{i} = {i}\n" * 20, encoding="utf-8")

    result = scan_directory(tmp_path)
    assert result.files_scanned == 50
    assert result.nti1_score >= 0


def test_oversized_file_skipped(tmp_path: Path) -> None:
    oversized = tmp_path / "huge.py"
    # Create an 11 MB file
    oversized.write_bytes(b"# huge file\n" * (1024 * 1024))
    result = scan_directory(tmp_path)
    assert result.files_scanned == 1
    # Oversized file is skipped by AST parser cleanly
    assert len(result.findings) == 0
