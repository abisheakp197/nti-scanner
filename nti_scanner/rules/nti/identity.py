"""NTI-1 Pillar 1: Identity."""
import ast
from pathlib import Path
from typing import ClassVar

from nti_scanner.rules.base import BaseRule, Finding, RuleMeta, ast_identifiers


class IdentityRule(BaseRule):
    meta = RuleMeta(id="NTI-IDENT-001", category="Compliance", severity="info", confidence="medium",
                    description="Agent entry point with no cryptographic identity binding", cwe="",
                    remediation="Bind each agent to a signing identity and verify it before use.")
    PQC_KEYWORDS: ClassVar[set[str]] = {"dilithium", "kyber", "ml-dsa", "ml-kem", "pqc"}
    BINDING_MARKERS: ClassVar[tuple[str, ...]] = ("callbackhandler", "identity", "signer", "keypair")

    def _has_identity_binding(self, idents: set[str]) -> bool:
        if any(kw in idents for kw in self.PQC_KEYWORDS):
            return True
        return any(marker in ident for ident in idents for marker in self.BINDING_MARKERS)

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        findings = []
        agent_nodes: list[ast.AST] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fname = _name(node.func)
                if fname in {"Agent", "ChatOpenAI", "LLMChain"} or "agent" in fname.lower():
                    agent_nodes.append(node)
        if not agent_nodes:
            return []
        idents = ast_identifiers(tree)
        if not self._has_identity_binding(idents):
            findings.append(self.make_finding(path, agent_nodes[0], "Agent declared with no cryptographic identity binding in this module."))
        return findings


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""
