"""NTI-1 Pillar 3: BFT Consensus."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.rules.base import Finding


class ConsensusRule(BaseRule):
    meta = RuleMeta(id="NTI-CONS-001", category="Consensus", severity="medium", confidence="low",
                    description="Multi-agent system without BFT consensus", cwe="CWE-703",
                    remediation="Use NTI BFT consensus for multi-agent systems.")
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        agent_count = 0
        first_node = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _name(node.func) == "Agent":
                agent_count += 1
                if first_node is None: first_node = node
        if agent_count < 2: return []
        content = path.read_text(errors="ignore").lower()
        if any(kw in content for kw in {"consensus", "voter", "bft", "threshold"}): return []
        return [self.make_finding(path, first_node, f"Multi-agent system ({agent_count} agents) without BFT consensus.")]


def _name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    return ""
