"""NTI-1 Pillar 4: Audit."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class AuditRule(BaseRule):
    meta = RuleMeta(
        id="NTI-AUDIT-001",
        category="Audit",
        severity="high",
        confidence="high",
        description="Agent actions are not logged to an immutable or structured audit trail",
        cwe="CWE-778",
        remediation="Log agent actions, inputs, and outputs to an append-only audit trail or callback handler.",
    )

    AUDIT_KEYWORDS = {"logging", "logger", "audit", "trace", "telemetry", "event_log", "log_action"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        has_audit = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in {"logging", "structlog", "loguru"}:
                        has_audit = True
            elif isinstance(node, ast.ImportFrom):
                if node.module and any(m in node.module for m in ["logging", "structlog", "loguru"]):
                    has_audit = True
            elif isinstance(node, ast.Name) and any(k in node.id.lower() for k in self.AUDIT_KEYWORDS):
                has_audit = True

        if not has_audit:
            first_node = next(ast.walk(tree), None)
            if first_node:
                findings.append(
                    self.make_finding(
                        path,
                        first_node,
                        "Agent file lacks structured logging or immutable audit tracking for actions.",
                    )
                )

        return findings
