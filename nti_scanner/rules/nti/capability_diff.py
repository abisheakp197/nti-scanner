"""Capability Diff Rule."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class CapabilityDiffRule(BaseRule):
    meta = RuleMeta(
        id="NTI-CAP-DIFF-001",
        category="Governance",
        severity="medium",
        confidence="high",
        description="Agent capabilities are modified or dynamically injected at runtime without static registration",
        cwe="CWE-269",
        remediation="Statically register all agent tools and capabilities prior to agent initialization.",
    )

    DYNAMIC_TOOL_METHODS = {"add_tool", "register_tool", "append", "extend"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in self.DYNAMIC_TOOL_METHODS and "tool" in node.func.attr.lower():
                        findings.append(
                            self.make_finding(
                                path,
                                node,
                                f"Dynamic capability modification detected via method '{node.func.attr}'.",
                            )
                        )

        return findings
