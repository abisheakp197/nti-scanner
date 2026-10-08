"""NTI-1 Pillar 2: Governance."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class GovernanceRule(BaseRule):
    meta = RuleMeta(
        id="NTI-GOV-001",
        category="Governance",
        severity="high",
        confidence="medium",
        description="Agent executes actions without human-in-the-loop or policy checks",
        cwe="CWE-270",
        remediation="Implement policy evaluation or human confirmation callbacks before invoking agent tools or critical state changes.",
    )

    GOV_KEYWORDS = {"policy", "governance", "approve", "confirm", "human_in_loop", "hitl", "permission", "authorize"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        has_gov = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and any(k in node.id.lower() for k in self.GOV_KEYWORDS):
                has_gov = True
            elif isinstance(node, ast.Attribute) and any(k in node.attr.lower() for k in self.GOV_KEYWORDS):
                has_gov = True

        if not has_gov:
            first_node = next(ast.walk(tree), None)
            if first_node:
                findings.append(
                    self.make_finding(
                        path,
                        first_node,
                        "Agent code lacks explicit governance controls or human-in-the-loop approval workflows.",
                    )
                )

        return findings
