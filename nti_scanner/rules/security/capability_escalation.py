"""Capability Escalation Rule."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class CapabilityEscalationRule(BaseRule):
    meta = RuleMeta(
        id="SEC-CAP-001",
        category="Security",
        severity="high",
        confidence="medium",
        description="Agent attempts privilege escalation or unauthorized capability granting",
        cwe="CWE-269",
        remediation="Enforce strict role-based capability boundaries and avoid granting root/admin capabilities to agents.",
    )

    ESCALATION_KEYWORDS = {"sudo", "chmod", "chown", "grant_all", "admin", "superuser", "root"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if any(k in node.value.lower() for k in self.ESCALATION_KEYWORDS):
                    findings.append(
                        self.make_finding(
                            path,
                            node,
                            "Privilege escalation keyword detected in agent instruction or command execution.",
                        )
                    )

        return findings
