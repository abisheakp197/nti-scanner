"""HTML report."""
from html import escape

from nti_scanner.scanner import ScanResult


def render_html(result: ScanResult) -> str:
    findings_html = ""
    for f in result.findings:
        findings_html += (
            f'<div class="finding {f.severity}"><div><strong>{f.severity.upper()}</strong> - '
            f'{f.rule_id}</div><div>{escape(f.message)}</div><div>{escape(f.file)}:{f.line}</div></div>'
        )
    pillars_html = "".join(f"<div><span>{p}</span><span>{s}/100</span></div>" for p, s in result.pillar_scores.items())
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>nti-scanner</title></head><body>"
        f"<h1>NTI-1 Report</h1><div>{result.nti1_score}/100</div>"
        f"<p>{result.files_scanned} files - {len(result.findings)} findings</p>"
        f"<h2>Pillars</h2>{pillars_html}<h2>Findings</h2>{findings_html}</body></html>"
    )
