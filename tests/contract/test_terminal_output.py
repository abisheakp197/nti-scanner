"""Contract tests for terminal output rendering."""
from rich.console import Console
from nti_scanner.report.terminal import render_terminal
from nti_scanner.scanner import ScanResult, Finding


def test_render_terminal_output(tmp_path):
    console = Console(record=True, width=120)
    result = ScanResult(path=str(tmp_path), nti1_score=85, files_scanned=2, lines_scanned=50)
    result.findings.append(Finding(
        rule_id="SEC-CMD-001", category="Security", severity="high",
        confidence="high", message="Command injection", file="test.py", line=5, column=0, cwe="CWE-78"
    ))
    render_terminal(result, console)
    output = console.export_text()
    assert "NTI-1 Score" in output
    assert "85/100" in output
    assert "SEC-CMD-001" in output
    assert "CWE-78" in output
