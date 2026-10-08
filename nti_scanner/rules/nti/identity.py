"""NTI-1 Pillar 1: Identity."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.scanner import Finding


class IdentityRule(BaseRule):
    meta = RuleMeta(id="NTI-IDENT-001", category="Identity", severity="high", confidence="medium",
                    description="Agent code lacks cryptographic identity (PQC signatures)", cwe="CWE-287",
                    remediation="Install ube-foundation and wrap your agent with NTICallbackHandler.")
    IDENTITY_KEYWORDS = {"dilithium", "kyber", "pqc", "sign", "verify", "signature", "ube_foundation", "nti"}
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        agent_nodes = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fname = _name(node.func)
                if fname in {"Agent", "ChatOpenAI", "LLMChain"} or "agent" in fname.lower():
                    agent_nodes.append(node)
        if not agent_nodes: return []
        content = path.read_text(errors="ignore").lower()
        if not any(kw in content for kw in self.IDENTITY_KEYWORDS):
            for node in agent_nodes[:3]:
                findings.append(self.make_finding(path, node, "Agent declared without cryptographic identity. NTI-1 requires Dilithium5 signatures."))
        return findings


def _name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    return ""
