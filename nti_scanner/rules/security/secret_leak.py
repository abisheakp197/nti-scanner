"""Detect hardcoded secrets."""
import ast
from pathlib import Path
from typing import ClassVar

from nti_scanner.rules.base import BaseRule, Finding, RuleMeta


class SecretLeakRule(BaseRule):
    meta = RuleMeta(id="SEC-SECRET-001", category="Security", severity="critical", confidence="high",
                    description="Hardcoded API key or secret", cwe="CWE-798",
                    remediation="Use environment variables.")
    SECRET_PREFIXES: ClassVar[set[str]] = {"sk-", "sk_live_", "sk_test_", "AIza", "AKIA", "ghp_", "xoxb-", "xoxp-"}

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                v = node.value
                if len(v) < 20 or len(v) > 200:
                    continue
                if any(v.startswith(p) for p in self.SECRET_PREFIXES):
                    findings.append(self.make_finding(path, node, "Hardcoded secret detected."))
        return findings[:3]
