"""Detect hardcoded secrets that look like real credentials."""
import ast
from pathlib import Path
from typing import ClassVar

from nti_scanner.rules.base import BaseRule, Finding, RuleMeta


class SecretLeakRule(BaseRule):
    meta = RuleMeta(id="SEC-SECRET-001", category="Security", severity="critical", confidence="high",
                    description="Hardcoded API key or secret", cwe="CWE-798",
                    remediation="Use environment variables.")
    SECRET_PREFIXES: ClassVar[set[str]] = {"sk-", "sk_live_", "sk_test_", "AIza", "AKIA", "ghp_", "xoxb-", "xoxp-"}

    # Fixture values read as placeholders ("sk-very-secret-value",
    # "sk-test-live-server-12345") rather than issued credentials.
    PLACEHOLDER_MARKERS: ClassVar[tuple[str, ...]] = (
        "secret", "test", "dummy", "fake", "example", "sample", "placeholder",
        "should-not", "redact", "leak", "probe", "shared", "verify", "abc123",
        "12345", "0000", "xxxx", "your-", "<", "changeme",
    )

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        parts = set(path.parts)
        if parts & {"tests", "test", "testing", "__tests__"} or path.name.startswith("test_"):
            return []

        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                v = node.value
                if len(v) < 20 or len(v) > 200:
                    continue
                if not any(v.startswith(p) for p in self.SECRET_PREFIXES):
                    continue
                low = v.lower()
                if any(marker in low for marker in self.PLACEHOLDER_MARKERS):
                    continue
                if not any(c.isdigit() for c in v):
                    continue
                findings.append(self.make_finding(path, node, "Hardcoded credential-like string."))
        return findings[:3]
