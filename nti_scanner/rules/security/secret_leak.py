"""Detect hardcoded secrets."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.rules.base import Finding


class SecretLeakRule(BaseRule):
    meta = RuleMeta(id="SEC-SECRET-001", category="Security", severity="critical", confidence="high",
                    description="Hardcoded API key or secret", cwe="CWE-798",
                    remediation="Use environment variables.")
    SECRET_PREFIXES = {"sk-", "sk_live_", "sk_test_", "AIza", "AKIA", "ghp_", "xoxb-", "xoxp-"}
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                v = node.value
                if len(v) < 20 or len(v) > 200: continue
                if any(v.startswith(p) for p in self.SECRET_PREFIXES):
                    findings.append(self.make_finding(path, node, "Hardcoded secret detected."))
        return findings[:3]
