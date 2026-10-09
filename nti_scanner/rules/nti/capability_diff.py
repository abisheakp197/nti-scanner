"""NTI-unique: Detect unauthorized tool capabilities."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta, Finding


class CapabilityDiffRule(BaseRule):
    meta = RuleMeta(id="NTI-CAPDIFF-001", category="Governance", severity="critical", confidence="high",
                    description="Tool declared but never granted as a capability", cwe="CWE-862",
                    remediation="Every tool must have grant_capability().")
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        declared_tools = set()
        granted_caps = set()
        tool_nodes = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    name = _name(dec.func if isinstance(dec, ast.Call) else dec)
                    if name in {"tool", "function_tool"}:
                        declared_tools.add(node.name)
                        tool_nodes[node.name] = node
            if isinstance(node, ast.Call):
                if _name(node.func) == "grant_capability" and node.args:
                    if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        granted_caps.add(node.args[0].value)
        if not declared_tools: return []
        unguarded = declared_tools - granted_caps
        if not unguarded: return []
        content = path.read_text(errors="ignore")
        if "grant_capability" not in content:
            node = next((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), tree)
            return [self.make_finding(path, node, f"Tools declared but no grant_capability(). All {len(declared_tools)} tools unauthorized.")]
        findings = []
        for tool_name in unguarded:
            node = tool_nodes.get(tool_name, tree)
            findings.append(self.make_finding(path, node, f"Tool '{tool_name}' declared but not granted capability via grant_capability()."))
        return findings


def _name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    return ""
