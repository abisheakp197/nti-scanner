"""Rules for Agent-to-Agent (A2A) protocol security."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.rules.base import Finding


class A2ARule(BaseRule):
    meta = RuleMeta(id="SEC-A2A-001", category="Security", severity="high", confidence="medium",
                    description="Agent-to-Agent communication without identity verification", cwe="CWE-287",
                    remediation="A2A messages must be cryptographically signed.")
    A2A_INDICATORS = {"a2a", "agentcard", "a2aclient", "a2aserver", "agent_to_agent"}
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        content = path.read_text(errors="ignore").lower()
        if not any(kw in content for kw in self.A2A_INDICATORS): return []
        has_identity = any(kw in content for kw in ["signature", "verify", "dilithium", "nti", "identity"])
        if not has_identity:
            node = next(iter(ast.walk(tree)), tree)
            return [self.make_finding(path, node, "A2A communication without identity verification.")]
        return []
