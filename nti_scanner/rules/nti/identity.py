"""NTI-1 Pillar 1: Identity."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class IdentityRule(BaseRule):
    meta = RuleMeta(
        id="NTI-IDENT-001",
        category="Identity",
        severity="high",
        confidence="medium",
        description="Agent code lacks cryptographic identity (PQC signatures)",
        cwe="CWE-287",
        remediation="Install ube-foundation and wrap your agent with NTICallbackHandler, which enforces Dilithium5 signatures on every action.",
    )

    IDENTITY_KEYWORDS = {"dilithium", "kyber", "pqc", "sign", "verify", "signature", "ube_foundation", "nticallbackhandler", "agent_id"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        has_identity = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "ube_foundation" in alias.name or "pqc" in alias.name:
                        has_identity = True
            elif isinstance(node, ast.ImportFrom):
                if node.module and ("ube_foundation" in node.module or "pqc" in node.module):
                    has_identity = True
            elif isinstance(node, ast.Name):
                if node.id.lower() in self.IDENTITY_KEYWORDS:
                    has_identity = True

        if not has_identity:
            first_node = next(ast.walk(tree), None)
            if first_node:
                findings.append(
                    self.make_finding(
                        path,
                        first_node,
                        "Agent file lacks cryptographic identity or PQC verification mechanism.",
                    )
                )

        return findings
