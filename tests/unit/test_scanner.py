"""Unit tests for the scanner module."""
from click.testing import CliRunner
from nti_scanner.cli import main
from nti_scanner.scanner import scan_directory


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_rules():
    runner = CliRunner()
    result = runner.invoke(main, ["rules"])
    assert result.exit_code == 0
    assert "NTI-IDENT-001" in result.output


def test_scan_directory(tmp_path):
    sample = tmp_path / "agent.py"
    sample.write_text("""
from langchain import Agent
def my_tool():
    pass
""")
    res = scan_directory(tmp_path)
    assert res.files_scanned == 1
    assert "langchain" in res.frameworks
