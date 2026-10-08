"""Secret Leak Rule."""

import ast
import re
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class SecretLeakRule(BaseRule):
    meta = RuleMeta(
        id="SEC-SECRET-001",
        category="Security",
        severity="critical",
        confidence="high",
        description="Hardcoded secret or API key found in code",
        cwe="CWE-798",
        remediation="Store secrets in environment variables or key management services (KMS).",
    )

    SECRET_PATTERNS = [
        re.compile(r"sk-[a-zA-Z0-9]{32,}", re.IGNORECASE),
        re.compile(r"ghp_[a-zA-Z0-9]{36}", re.IGNORECASE),
        re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
        re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE),
    ]

    SECRET_KEY_NAMES = {"api_key", "secret", "password", "token", "private_key", "openai_api_key", "anthropic_api_key"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.lower() in self.SECRET_KEY_NAMES:
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value
                            if len(val) > 8 and val not in {"YOUR_API_KEY", "env_var", "dummy"}:
                                findings.append(
                                    self.make_finding(
                                        path,
                                        node,
                                        f"Hardcoded value assigned to secret variable '{target.id}'.",
                                    )
                                )

            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for pattern in self.SECRET_PATTERNS:
                    if pattern.search(node.value):
                        findings.append(
                            self.make_finding(
                                path,
                                node,
                                "Potential API key or token matched hardcoded secret regex pattern.",
                            )
                        )

        return findings
