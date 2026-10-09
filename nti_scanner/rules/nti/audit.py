"""NTI-1 Pillar 4: Audit."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.rules.base import Finding


class AuditRule(BaseRule):
    meta = RuleMeta(id="NTI-AUDIT-001", category="Audit", severity="high", confidence="high",
                    description="No Merkle-chained audit trail detected", cwe="CWE-778",
                    remediation="Install ube-foundation for Merkle-chained audit.")
    AUDIT_KEYWORDS = {"audit", "merkle", "audit_event", "verify_history", "log_event", "ube_foundation"}
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        has_agent = False
        first_node = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and "Agent" in _name(node.func):
                has_agent = True
                first_node = node
                break
        if not has_agent: return []
        content = path.read_text(errors="ignore").lower()
        if any(kw in content for kw in self.AUDIT_KEYWORDS): return []
        return [self.make_finding(path, first_node, "Agent without audit trail. NTI-1 requires Merkle-chained logs.")]


def _name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    return ""
