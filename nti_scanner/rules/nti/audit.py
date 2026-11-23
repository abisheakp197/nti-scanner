"""NTI-1 Pillar 4 (Audit): report absence of a tamper-evident audit trail.

This is a conformance gap in the audited project, not an exploitable defect in
it, so it is reported as an info-severity Compliance finding.
"""
import ast
from pathlib import Path
from typing import ClassVar
from nti_scanner.rules.base import BaseRule, Finding, RuleMeta, ast_identifiers


class AuditRule(BaseRule):
    meta = RuleMeta(
        id="NTI-AUDIT-001",
        category="Compliance",
        severity="info",
        confidence="medium",
        description="Agent entry point without a tamper-evident audit trail",
        cwe="",
        remediation="Record each agent action in an append-only, hash-chained log.",
    )
    AUDIT_KEYWORDS: ClassVar[set[str]] = {
        "audit", "merkle", "audit_event", "verify_history", "log_event",
        "append_only", "hash_chain",
    }

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        entry: ast.AST | None = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and "Agent" in _name(node.func):
                entry = node
                break
        if entry is None:
            return []
        idents = ast_identifiers(tree)
        if any(kw in idents for kw in self.AUDIT_KEYWORDS):
            return []
        return [
            self.make_finding(
                path,
                entry,
                "Agent constructed with no audit-trail implementation in this module.",
            )
        ]


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""
