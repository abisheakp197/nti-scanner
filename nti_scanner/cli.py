"""Command-line interface."""
import sys
from pathlib import Path
import click
from rich.console import Console
from nti_scanner.scanner import scan_directory
from nti_scanner.report.terminal import render_terminal
from nti_scanner.report.json_report import render_json
from nti_scanner.report.sarif import render_sarif
from nti_scanner.report.html import render_html
console = Console()


@click.group()
@click.version_option()
def main():
    """nti-scanner: NTI-1 compliance and AI agent security scanner."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False))
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "sarif", "html"]), default="terminal")
@click.option("--output", "-o", type=click.Path(), default=None)
@click.option("--min-score", default=0)
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low", "info"]), default="info")
@click.option("--exclude", multiple=True)
def scan(path, fmt, output, min_score, severity, exclude):
    """Scan a directory for NTI-1 compliance and AI agent security issues."""
    if fmt == "terminal":
        console.print(f"[bold cyan]nti-scanner v{__import__('nti_scanner').__version__}[/bold cyan]")
        console.print(f"Scanning [bold]{path}[/bold]...\n")
    result = scan_directory(Path(path).resolve(), min_severity=severity, excludes=list(exclude))
    if fmt == "terminal":
        render_terminal(result, console)
    elif fmt == "json":
        content = render_json(result)
        if output: Path(output).write_text(content)
        else: console.print_json(content)
    elif fmt == "sarif":
        content = render_sarif(result)
        if output: Path(output).write_text(content)
        else: print(content)
    elif fmt == "html":
        content = render_html(result)
        if output: Path(output).write_text(content)
        else: print(content)
    if min_score and result.nti1_score < min_score:
        sys.exit(1)


@main.command()
def rules():
    """List all available rules."""
    from rich.table import Table
    from nti_scanner.rules.registry import RULES
    table = Table(title="Available Rules")
    table.add_column("ID", style="cyan")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Description")
    for r in RULES:
        table.add_row(r.meta.id, r.meta.category, r.meta.severity, r.meta.description[:60])
    console.print(table)


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False))
@click.option("--output", "-o", type=click.Path(), required=True)
def graph(path, output):
    """Build and export the agent behavior graph."""
    from pathlib import Path
    from nti_scanner.ast_analysis.parser import parse_python_file
    from nti_scanner.analysis.behavior_graph import build_behavior_graph, render_graph_json
    trees = {}
    for f in Path(path).rglob("*.py"):
        t = parse_python_file(f)
        if t: trees[f] = t
    graph_data = build_behavior_graph(trees)
    Path(output).write_text(render_graph_json(graph_data))
    console.print(f"[green]Graph written to {output}[/green]")


if __name__ == "__main__":
    main()
