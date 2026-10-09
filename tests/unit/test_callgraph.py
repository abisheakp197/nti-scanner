"""Unit tests for call graph construction."""
import ast
from nti_scanner.ast_analysis.callgraph import build_call_graph


def test_build_call_graph():
    code = """
def foo():
    bar()

def bar():
    pass
"""
    tree = ast.parse(code)
    graph = build_call_graph(tree)
    assert "foo" in graph
    assert "bar" in graph["foo"]
    assert "bar" in graph
    assert len(graph["bar"]) == 0
