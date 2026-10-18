"""NTI-1 Pillar 2: Governance."""
import ast
from pathlib import Path
from typing import ClassVar

from nti_scanner.rules.base import BaseRule, Finding, RuleMeta


class GovernanceRule(BaseRule):
    meta = RuleMeta(id="NTI-GOV-001", category="Governance", severity="critical", confidence="high",
                    description="Tool functions without zero-trust capability bounds", cwe="CWE-862",
                    remediation="Grant explicit capabilities per tool.")
    TOOL_DECORATORS: ClassVar[set[str]] = {"tool", "function_tool"}
    GOVERNANCE_KEYWORDS: ClassVar[set[str]] = {"grant_capability", "check_capability", "trustengine", "trust_engine", "nti", "policy"}

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        tool_functions: list[ast.AST] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if (isinstance(dec, ast.Call) and _name(dec.func) in self.TOOL_DECORATORS) or (isinstance(dec, ast.Name) and dec.id in self.TOOL_DECORATORS):
                        tool_functions.append(node)
        if not tool_functions:
            return []
        content = path.read_text(errors="ignore").lower()
        if not any(kw in content for kw in self.GOVERNANCE_KEYWORDS):
            return [self.make_finding(path, tool_functions[0], f"Found {len(tool_functions)} tool function(s) without governance.")]
        return []


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""
