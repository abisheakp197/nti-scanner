"""SSRF Rule."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class SSRRule(BaseRule):
    meta = RuleMeta(
        id="SEC-SSRF-001",
        category="Security",
        severity="high",
        confidence="medium",
        description="Unvalidated user input used as target URL for HTTP request",
        cwe="CWE-918",
        remediation="Validate target host against an allowlist of permitted IP addresses or domains before fetching.",
    )

    HTTP_CLIENTS = {"requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen", "aiohttp"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    func_name = f"{node.func.value.id}.{node.func.attr}"
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if func_name in self.HTTP_CLIENTS or any(c in func_name for c in ["requests.", "httpx."]):
                    if node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, (ast.Name, ast.JoinedStr, ast.BinOp)):
                            findings.append(
                                self.make_finding(
                                    path,
                                    node,
                                    f"HTTP request target URL in '{func_name}' is dynamically constructed and may be vulnerable to SSRF.",
                                )
                            )

        return findings
