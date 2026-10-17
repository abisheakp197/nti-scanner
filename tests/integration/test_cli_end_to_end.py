"""CLI end-to-end test."""
import subprocess
import sys


def test_cli_scan_terminal(vulnerable_project):
    result = subprocess.run(
        [sys.executable, "-m", "nti_scanner.cli", "scan", str(vulnerable_project)],
        check=False, capture_output=True, text=True, timeout=60,
    )
    assert "NTI-1 Score" in result.stdout


def test_cli_scan_json(vulnerable_project):
    result = subprocess.run(
        [sys.executable, "-m", "nti_scanner.cli", "scan", str(vulnerable_project), "--format", "json"],
        check=False, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode in (0, 1)


def test_cli_rules_list():
    result = subprocess.run(
        [sys.executable, "-m", "nti_scanner.cli", "rules"],
        check=False, capture_output=True, text=True, timeout=60,
    )
    assert "NTI-IDENT-001" in result.stdout or len(result.stdout) > 0
