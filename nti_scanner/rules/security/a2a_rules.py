"""A2A Rules."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class A2ARule(BaseRule):
    meta = RuleMeta(
        id="SEC-A2A-001",
        category="Security",
        severity="high",
        confidence="medium",
        description="Agent-to-Agent (A2A) protocol communication lacks mutual authentication or message signatures",
        cwe="CWE-306",
        remediation="Require signed JWTs or PQC Dilithium signatures on all inter-agent (A2A) messages.",
    )

    A2A_KEYWORDS = {"a2a", "agent2agent", "inter_agent", "agent_message"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        is_a2a = "Agent2Agent (A2A)" in frameworks

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "a2a" in alias.name.lower():
                        is_a2a = True
            elif isinstance(node, ast.ImportFrom):
                if node.module and "a2a" in node.module.lower():
                    is_a2a = True

        if is_a2a:
            has_signature = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and any(k in node.id.lower() for k in ["sign", "verify", "signature", "jwt", "pqc"]):
                    has_signature = True

            if not has_signature:
                first_node = next(ast.walk(tree), None)
                if first_node:
                    findings.append(
                        self.make_finding(
                            path,
                            first_node,
                            "A2A communication protocol implementation lacks message signature verification.",
                        )
                    )

        return findings
