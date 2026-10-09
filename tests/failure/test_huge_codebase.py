"""Failure mode test for huge codebase/many files."""
from nti_scanner.scanner import scan_directory


def test_huge_codebase_handled(tmp_path):
    nested = tmp_path
    for d in range(10):
        nested = nested / f"dir_{d}"
        nested.mkdir()
        for i in range(5):
            (nested / f"file_{i}.py").write_text(f"x_{i} = {i}\n" * 20)

    result = scan_directory(tmp_path)
    assert result.files_scanned == 50
    assert result.nti1_score >= 0
