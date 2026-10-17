"""Build a call graph from Python AST."""
import ast


def build_call_graph(tree: ast.AST) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            calls = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                    calls.add(sub.func.id)
            graph[node.name] = calls
    return graph
