"""LLM Trust Rule."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class LLMTrustRule(BaseRule):
    meta = RuleMeta(
        id="SEC-LLM-TRUST-001",
        category="Security",
        severity="medium",
        confidence="medium",
        description="Agent output used directly in high-privilege function call without validation",
        cwe="CWE-346",
        remediation="Sanitize and validate all LLM-generated output before passing it to system execution sinks.",
    )

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                    findings.append(
                        self.make_finding(
                            path,
                            node,
                            f"Direct execution via '{node.func.id}' presents critical LLM output trust violation.",
                        )
                    )

        return findings
