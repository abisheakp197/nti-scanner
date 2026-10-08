"""HTML report generator."""

import html
import json


def render_html(result) -> str:
    findings_rows = []
    for f in result.findings:
        findings_rows.append(f"""
        <tr>
            <td><code>{html.escape(f.rule_id)}</code></td>
            <td><span class="badge severity-{html.escape(f.severity.lower())}">{html.escape(f.severity.upper())}</span></td>
            <td>{html.escape(f.category)}</td>
            <td><code>{html.escape(f.file)}:{f.line}</code></td>
            <td>{html.escape(f.message)}</td>
            <td>{html.escape(f.remediation)}</td>
        </tr>
        """)

    pillar_cards = []
    for p, s in result.pillar_scores.items():
        color = "#22c55e" if s >= 80 else ("#eab308" if s >= 50 else "#ef4444")
        pillar_cards.append(f"""
        <div class="card">
            <h3>{html.escape(p)}</h3>
            <div class="score" style="color: {color};">{s}/100</div>
        </div>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NTI-1 Compliance & Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 2rem; background: #0f172a; color: #f8fafc; }}
        h1, h2 {{ color: #38bdf8; }}
        .header {{ border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 2rem; }}
        .cards {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
        .card {{ background: #1e293b; padding: 1.5rem; border-radius: 8px; flex: 1; min-width: 150px; text-align: center; border: 1px solid #334155; }}
        .score {{ font-size: 2rem; font-weight: bold; margin-top: 0.5rem; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; }}
        .badge {{ padding: 0.25rem 0.5rem; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
        .severity-critical {{ background: #7f1d1d; color: #fca5a5; }}
        .severity-high {{ background: #991b1b; color: #fca5a5; }}
        .severity-medium {{ background: #854d0e; color: #fef08a; }}
        .severity-low {{ background: #1e3a8a; color: #bfdbfe; }}
        .severity-info {{ background: #334155; color: #cbd5e1; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>nti-scanner Report</h1>
        <p><strong>Path:</strong> {html.escape(result.path)} | <strong>NTI-1 Overall Score:</strong> {result.nti1_score}/100</p>
        <p><strong>Frameworks Detected:</strong> {html.escape(', '.join(result.frameworks)) if result.frameworks else 'None'}</p>
    </div>

    <h2>NTI-1 Pillar Scores</h2>
    <div class="cards">
        {''.join(pillar_cards)}
    </div>

    <h2>Findings ({len(result.findings)})</h2>
    <table>
        <thead>
            <tr>
                <th>Rule ID</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Location</th>
                <th>Message</th>
                <th>Remediation</th>
            </tr>
        </thead>
        <tbody>
            {''.join(findings_rows) if findings_rows else '<tr><td colspan="6">No issues found.</td></tr>'}
        </tbody>
    </table>
</body>
</html>
"""
