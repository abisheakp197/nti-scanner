"""Unit tests for behavior graph building."""
import json
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.analysis.behavior_graph import build_behavior_graph, render_graph_json


def test_build_behavior_graph(tmp_python_file):
    f = tmp_python_file("from langchain.agents import AgentExecutor\nagent = AgentExecutor()")
    tree = parse_python_file(f)
    graph = build_behavior_graph({f: tree})
    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) >= 1


def test_render_graph_json(tmp_python_file):
    f = tmp_python_file("from langchain.agents import AgentExecutor\nagent = AgentExecutor()")
    tree = parse_python_file(f)
    graph = build_behavior_graph({f: tree})
    json_str = render_graph_json(graph)
    parsed = json.loads(json_str)
    assert "nodes" in parsed
