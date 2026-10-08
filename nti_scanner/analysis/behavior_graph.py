"""Build an agent behavior graph from AST."""
import ast
import json
from pathlib import Path
from typing import Dict, List


def build_behavior_graph(trees: Dict) -> dict:
    nodes = []
    edges = []
    for f, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _name(node.func)
                if name in {"Agent", "AgentExecutor", "Crew"}:
                    nodes.append({"id": f"{f}:{node.lineno}", "type": "agent", "name": name, "file": str(f)})
                elif name in {"execute_transfer", "delete_account", "read_account", "transfer"}:
                    nodes.append({"id": f"{f}:{node.lineno}", "type": "action", "name": name, "file": str(f)})
                elif name in {"os.system", "subprocess.run", "eval", "exec", "open"}:
                    nodes.append({"id": f"{f}:{node.lineno}", "type": "sink", "name": name, "file": str(f)})
    return {"nodes": nodes, "edges": edges}


def _name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    return ""


def render_graph_json(graph: dict) -> str:
    return json.dumps(graph, indent=2)
