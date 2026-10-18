"""NTI-1 Pillar 5: Persistence."""
import ast
from pathlib import Path
from typing import ClassVar

from nti_scanner.rules.base import BaseRule, Finding, RuleMeta


class PersistenceRule(BaseRule):
    meta = RuleMeta(id="NTI-PERS-001", category="Persistence", severity="low", confidence="low",
                    description="No state persistence with integrity verification", cwe="CWE-353",
                    remediation="Persist agent state with cryptographic integrity.")
    PERSISTENCE_KEYWORDS: ClassVar[set[str]] = {"persist", "save_state", "load_state", "verify_history", "integrity"}

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        agent_node: ast.AST | None = None
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and "Agent" in _name(n.func):
                agent_node = n
                break
        if agent_node is None:
            return []
        content = path.read_text(errors="ignore").lower()
        if any(kw in content for kw in self.PERSISTENCE_KEYWORDS):
            return []
        return [self.make_finding(path, agent_node, "Agent state persistence lacks cryptographic integrity checks.")]


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""
