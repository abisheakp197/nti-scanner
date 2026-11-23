"""NTI-1 Pillar 3: BFT Consensus."""
import ast
from pathlib import Path

from nti_scanner.rules.base import BaseRule, Finding, RuleMeta


class ConsensusRule(BaseRule):
    meta = RuleMeta(id="NTI-CONS-001", category="Compliance", severity="info", confidence="low",
                    description="Multi-agent system without a consensus or arbitration step", cwe="",
                    remediation="Add an explicit arbitration step for conflicting agent outputs.")
    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        agent_count = 0
        first_node: ast.AST | None = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _name(node.func) == "Agent":
                agent_count += 1
                if first_node is None:
                    first_node = node
        if agent_count < 2 or first_node is None:
            return []
        content = path.read_text(errors="ignore").lower()
        if any(kw in content for kw in ("consensus", "voter", "bft", "threshold")):
            return []
        return [self.make_finding(path, first_node, f"Multi-agent system ({agent_count} agents) with no consensus or arbitration step.")]


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""
