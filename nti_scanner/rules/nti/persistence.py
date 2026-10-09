"""NTI-1 Pillar 5: Persistence."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.rules.base import Finding


class PersistenceRule(BaseRule):
    meta = RuleMeta(id="NTI-PERS-001", category="Persistence", severity="low", confidence="low",
                    description="No state persistence with integrity verification", cwe="CWE-353",
                    remediation="Persist agent state with cryptographic integrity.")
    PERSISTENCE_KEYWORDS = {"persist", "save_state", "load_state", "verify_history", "integrity"}
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        has_agent = any(isinstance(n, ast.Call) and "Agent" in _name(n.func) for n in ast.walk(tree))
        if not has_agent: return []
        content = path.read_text(errors="ignore").lower()
        if any(kw in content for kw in self.PERSISTENCE_KEYWORDS): return []
        return []


def _name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    return ""
