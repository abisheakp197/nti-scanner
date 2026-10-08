"""Rich terminal renderer for scan results."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def render_terminal(result, console: Console):
    score_color = "green" if result.nti1_score >= 80 else ("yellow" if result.nti1_score >= 50 else "red")

    summary_panel = Panel(
        f"[bold]NTI-1 Compliance Score:[/bold] [{score_color}]{result.nti1_score}/100[/{score_color}]\n"
        f"[bold]Files Scanned:[/bold] {result.files_scanned} | [bold]Lines Scanned:[/bold] {result.lines_scanned}\n"
        f"[bold]Frameworks Detected:[/bold] {', '.join(result.frameworks) if result.frameworks else 'None'}",
        title="[bold cyan]Scan Summary[/bold cyan]",
        expand=False,
    )
    console.print(summary_panel)

    # Pillar Scores Table
    p_table = Table(title="NTI-1 Pillar Breakdown")
    p_table.add_column("Pillar", style="cyan")
    p_table.add_column("Score", style="bold")
    for pillar, score in result.pillar_scores.items():
        p_color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")
        p_table.add_row(pillar, f"[{p_color}]{score}/100[/{p_color}]")
    console.print(p_table)

    if not result.findings:
        console.print("\n[bold green]✓ No issues found![/bold green]")
        return

    # Findings Table
    f_table = Table(title=f"Findings ({len(result.findings)} total)")
    f_table.add_column("Rule ID", style="cyan")
    f_table.add_column("Severity", style="bold")
    f_table.add_column("File:Line")
    f_table.add_column("Message")

    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for f in result.findings:
        color = severity_colors.get(f.severity, "white")
        f_table.add_row(
            f.rule_id,
            f"[{color}]{f.severity.upper()}[/{color}]",
            f"{f.file}:{f.line}",
            f.message[:80],
        )

    console.print(f_table)
