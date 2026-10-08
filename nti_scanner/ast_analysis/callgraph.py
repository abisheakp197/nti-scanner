"""Build a call graph from Python AST."""

import ast
from typing import Dict, Set


def build_call_graph(tree: ast.AST) -> Dict[str, Set[str]]:
    graph: Dict[str, Set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            calls = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                    calls.add(sub.func.id)
            graph[node.name] = calls
    return graph
