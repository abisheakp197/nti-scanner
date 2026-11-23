"""NTI-1 Pillar 2 (Governance): report tools lacking explicit capability bounds.

Absence of a capability system is an architecture choice in the audited project,
not a defect in this file, so it is an info-severity Compliance finding. The
previous implementation fired `critical` whenever the file did not contain the
literal string "nti", which measured vendor adoption rather than security.
"""
import ast
from pathlib import Path
from typing import ClassVar
from nti_scanner.rules.base import BaseRule, Finding, RuleMeta, ast_identifiers


class GovernanceRule(BaseRule):
    meta = RuleMeta(
        id="NTI-GOV-001",
        category="Compliance",
        severity="info",
        confidence="medium",
        description="Tool definitions without explicit per-call capability grants",
        cwe="",
        remediation="Check an explicit capability grant before each tool invocation.",
    )
    TOOL_DECORATORS: ClassVar[set[str]] = {"tool", "function_tool"}
    GOVERNANCE_KEYWORDS: ClassVar[set[str]] = {
        "grant_capability", "check_capability", "capability", "trust_engine",
        "policy", "authorize", "permission_check",
    }

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        tool_functions: list[ast.AST] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    target = dec.func if isinstance(dec, ast.Call) else dec
                    if _name(target) in self.TOOL_DECORATORS:
                        tool_functions.append(node)
                        break
        if not tool_functions:
            return []
        idents = ast_identifiers(tree)
        if any(kw in idents for kw in self.GOVERNANCE_KEYWORDS):
            return []
        return [
            self.make_finding(
                path,
                tool_functions[0],
                f"{len(tool_functions)} tool function(s) defined with no capability check in this module.",
            )
        ]


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""
