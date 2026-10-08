"""Rich terminal renderer."""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel


SEVERITY_COLORS = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "blue"}


def render_terminal(result, console: Console):
    score = result.nti1_score
    if score >= 90: color, grade = "green", "A"
    elif score >= 75: color, grade = "cyan", "B"
    elif score >= 50: color, grade = "yellow", "C"
    elif score >= 25: color, grade = "orange3", "D"
    else: color, grade = "red", "F"
    console.print(Panel.fit(f"[bold {color}]NTI-1 Score: {score}/100 (Grade {grade})[/bold {color}]\n"
                            f"Files scanned: {result.files_scanned}  |  Lines: {result.lines_scanned}  |  Findings: {len(result.findings)}\n"
                            f"Frameworks detected: {', '.join(result.frameworks) or 'none'}", title="nti-scanner"))
    if result.pillar_scores:
        table = Table(title="Pillar Breakdown")
        table.add_column("Pillar", style="cyan")
        table.add_column("Score", justify="right")
        for p, s in result.pillar_scores.items():
            color = "green" if s >= 80 else "yellow" if s >= 50 else "red"
            table.add_row(p, f"[{color}]{s}/100[/]")
        console.print(table)
    if result.findings:
        t = Table(title=f"Findings ({len(result.findings)})")
        t.add_column("Severity")
        t.add_column("Rule")
        t.add_column("CWE")
        t.add_column("Message")
        t.add_column("File:Line")
        for f in result.findings[:30]:
            t.add_row(f"[{SEVERITY_COLORS.get(f.severity, 'white')}]{f.severity.upper()}[/]",
                      f.rule_id, f.cwe or "-", f.message[:70], f"{f.file.split('/')[-1]}:{f.line}")
        console.print(t)
    console.print()
    console.print("[bold]Fix your score:[/bold] pip install ube-foundation")
    console.print("[dim]Spec: https://abisheakp197.github.io/nti-spec/[/dim]")
