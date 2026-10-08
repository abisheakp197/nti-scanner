"""Lightweight taint tracking."""
import ast
from typing import Set


USER_INPUT_SOURCES = {"input", "request.form", "request.json", "request.args", "sys.stdin.read", "sys.argv"}
UNSAFE_SINKS = {"eval", "exec", "os.system", "subprocess.run", "subprocess.Popen", "subprocess.call", "pickle.loads", "yaml.load", "os.popen"}


def find_tainted_calls(tree: ast.AST) -> list:
    findings = []
    tainted_names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if _is_user_input(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        tainted_names.add(target.id)
        if isinstance(node, ast.Call):
            func_name = _get_call_name(node)
            if func_name in UNSAFE_SINKS:
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id in tainted_names:
                        findings.append({"line": node.lineno, "col": node.col_offset, "sink": func_name, "source": arg.id})
    return findings


def _is_user_input(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        return _get_call_name(node) in USER_INPUT_SOURCES
    return False


def _get_call_name(node: ast.Call) -> str:
    parts = []
    cur = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))
