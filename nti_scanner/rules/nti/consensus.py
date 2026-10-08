"""NTI-1 Pillar 3: Consensus."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class ConsensusRule(BaseRule):
    meta = RuleMeta(
        id="NTI-CONS-001",
        category="Consensus",
        severity="medium",
        confidence="medium",
        description="Multi-agent decisions lack quorum or consensus validation",
        cwe="CWE-345",
        remediation="Ensure multi-agent workflows collect consensus or quorum votes before executing high-impact actions.",
    )

    CONSENSUS_KEYWORDS = {"consensus", "quorum", "vote", "majority", "multi_party", "bft", "agreement"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        has_consensus = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and any(k in node.id.lower() for k in self.CONSENSUS_KEYWORDS):
                has_consensus = True
            elif isinstance(node, ast.Attribute) and any(k in node.attr.lower() for k in self.CONSENSUS_KEYWORDS):
                has_consensus = True

        if not has_consensus:
            first_node = next(ast.walk(tree), None)
            if first_node:
                findings.append(
                    self.make_finding(
                        path,
                        first_node,
                        "Multi-agent interactions or tool invocations lack multi-party consensus verification.",
                    )
                )

        return findings
