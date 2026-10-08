"""Tests for nti-scanner CLI, scanner, and rules."""
import ast
from pathlib import Path
from click.testing import CliRunner
from nti_scanner.cli import main
from nti_scanner.scanner import scan_directory
from nti_scanner.rules.registry import RULES
from nti_scanner.framework.detector import detect_frameworks
from nti_scanner.ast_analysis.parser import parse_python_file, get_source_segment
from nti_scanner.ast_analysis.taint import find_tainted_calls
from nti_scanner.ast_analysis.callgraph import build_call_graph


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


def test_parser(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("x = 1\n")
    tree = parse_python_file(f)
    assert tree is not None
    assert get_source_segment(f, tree.body[0]) == "x = 1"


def test_taint():
    code = """
x = input()
eval(x)
"""
    tree = ast.parse(code)
    tainted = find_tainted_calls(tree)
    assert len(tainted) == 1
    assert tainted[0]["sink"] == "eval"


def test_callgraph():
    code = """
def foo():
    bar()
"""
    tree = ast.parse(code)
    graph = build_call_graph(tree)
    assert "foo" in graph
    assert "bar" in graph["foo"]


def test_rules_registered():
    assert len(RULES) == 19
