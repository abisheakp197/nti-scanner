"""Detect path traversal in file operations."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.rules.base import Finding


class PathTraversalRule(BaseRule):
    meta = RuleMeta(id="SEC-PATH-001", category="Security", severity="high", confidence="medium",
                    description="Potential path traversal in file operation", cwe="CWE-22",
                    remediation="Validate file paths with os.path.realpath().")
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fname = _name(node.func)
                if fname in {"open", "remove", "unlink", "rmtree"}:
                    for arg in node.args:
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                            findings.append(self.make_finding(path, node, f"Concatenated path passed to {fname}()"))
        return findings[:3]


def _name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    return ""
