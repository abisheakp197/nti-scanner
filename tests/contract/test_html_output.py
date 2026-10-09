"""Contract tests for HTML report output."""
from nti_scanner.report.html import render_html
from nti_scanner.scanner import ScanResult, Finding


def test_render_html_structure(tmp_path):
    result = ScanResult(path=str(tmp_path), nti1_score=90)
    result.findings.append(Finding(
        rule_id="SEC-CMD-001", category="Security", severity="high",
        confidence="high", message="Command injection", file="test.py", line=10, column=0
    ))
    html = render_html(result)
    assert "<!DOCTYPE html>" in html
    assert "NTI-1 Report" in html
    assert "SEC-CMD-001" in html
    assert "Command injection" in html
