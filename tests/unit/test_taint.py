"""Unit tests for taint analysis."""
import ast
from nti_scanner.ast_analysis.taint import find_tainted_calls


def test_taint_flow_detected():
    code = """
x = input()
eval(x)
"""
    tree = ast.parse(code)
    tainted = find_tainted_calls(tree)
    assert len(tainted) == 1
    assert tainted[0]["sink"] == "eval"
    assert tainted[0]["source"] == "x"


def test_untainted_variable_no_finding():
    code = """
x = "safe"
eval(x)
"""
    tree = ast.parse(code)
    tainted = find_tainted_calls(tree)
    assert len(tainted) == 0
