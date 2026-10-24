"""CLI --fix option integration tests."""
import os
from pathlib import Path

from click.testing import CliRunner

from nti_scanner.cli import main


def test_cli_fix_option(tmp_path: Path):
    agent_file = tmp_path / "agent.py"
    agent_file.write_text("agent = AgentExecutor()\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--fix"])
    assert result.exit_code == 0
    assert "NTI Auto-Fix applied" in result.output

    assert (tmp_path / ".github" / "workflows" / "nti-scan.yml").exists()
    assert (tmp_path / "requirements.txt").exists()
    assert (tmp_path / "README.md").exists()
    assert "from langchain_nti import NTICallbackHandler" in agent_file.read_text(encoding="utf-8")


def test_cli_fix_flag_on_main(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    agent_file = tmp_path / "agent.py"
    agent_file.write_text("crew = Crew()\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["--fix"])
    assert result.exit_code == 0
    assert "NTI Auto-Fix applied" in result.output
    assert (tmp_path / ".github" / "workflows" / "nti-scan.yml").exists()
