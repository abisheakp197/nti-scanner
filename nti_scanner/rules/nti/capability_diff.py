"""NTI-1 Pillar 2 (Governance): tools declared but never capability-granted."""
import ast
from pathlib import Path
from nti_scanner.rules.base import BaseRule, Finding, RuleMeta


class CapabilityDiffRule(BaseRule):
    meta = RuleMeta(
        id="NTI-CAPDIFF-001",
        category="Compliance",
        severity="info",
        confidence="medium",
        description="Tool declared but never granted an explicit capability",
        cwe="",
        remediation="Grant an explicit capability for every declared tool.",
    )

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        declared: set[str] = set()
        granted: set[str] = set()
        nodes: dict[str, ast.AST] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    target = dec.func if isinstance(dec, ast.Call) else dec
                    if _name(target) in {"tool", "function_tool"}:
                        declared.add(node.name)
                        nodes[node.name] = node
            if (
                isinstance(node, ast.Call)
                and _name(node.func) == "grant_capability"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                granted.add(node.args[0].value)
        unguarded = declared - granted
        if not declared or not unguarded:
            return []
        return [
            self.make_finding(
                path,
                nodes.get(next(iter(sorted(unguarded))), tree),
                f"{len(unguarded)} of {len(declared)} tool(s) declared without grant_capability().",
            )
        ]


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""
