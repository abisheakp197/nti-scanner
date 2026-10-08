"""Unit tests for nti-scanner."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nti_scanner.cli import main
from nti_scanner.scanner import scan_directory
from nti_scanner.analysis.behavior_graph import build_behavior_graph, render_graph_json
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.report.json_report import render_json
from nti_scanner.report.sarif import render_sarif
from nti_scanner.report.html import render_html


@pytest.fixture
def sample_vulnerable_agent_file(tmp_path):
    agent_code = """
import os
import sqlite3
import pickle
from langchain import Agent

OPENAI_API_KEY = "sk-12345678901234567890123456789012"

def process_query(user_input):
    prompt = f"System: Process command {user_input}"
    cmd = f"echo {user_input}"
    os.system(cmd)
    data = pickle.loads(user_input)
    agent = Agent()
    return data
"""
    file_path = tmp_path / "vulnerable_agent.py"
    file_path.write_text(agent_code)
    return tmp_path


def test_scan_directory(sample_vulnerable_agent_file):
    result = scan_directory(sample_vulnerable_agent_file)
    assert result.files_scanned == 1
    assert "LangChain" in result.frameworks
    assert len(result.findings) > 0

    rule_ids = {f.rule_id for f in result.findings}
    assert "SEC-SECRET-001" in rule_ids
    assert "SEC-PROMPT-001" in rule_ids
    assert "SEC-CMD-001" in rule_ids
    assert "SEC-DESER-001" in rule_ids


def test_cli_rules_command():
    runner = CliRunner()
    res = runner.invoke(main, ["rules"])
    assert res.exit_code == 0
    assert "NTI-IDENT-001" in res.output
    assert "SEC-PROMPT-001" in res.output


def test_cli_scan_command(sample_vulnerable_agent_file):
    runner = CliRunner()
    res = runner.invoke(main, ["scan", str(sample_vulnerable_agent_file), "--format", "json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert data["nti1_score"] < 100
    assert len(data["findings"]) > 0


def test_behavior_graph(sample_vulnerable_agent_file):
    file_path = sample_vulnerable_agent_file / "vulnerable_agent.py"
    tree = parse_python_file(file_path)
    trees = {file_path: tree}
    graph = build_behavior_graph(trees)
    assert len(graph["nodes"]) > 0
    json_out = render_graph_json(graph)
    assert "vulnerable_agent.py" in json_out


def test_reports(sample_vulnerable_agent_file):
    result = scan_directory(sample_vulnerable_agent_file)
    json_str = render_json(result)
    assert "findings" in json_str

    sarif_str = render_sarif(result)
    sarif_doc = json.loads(sarif_str)
    assert sarif_doc["version"] == "2.1.0"

    html_str = render_html(result)
    assert "<html" in html_str.lower()
