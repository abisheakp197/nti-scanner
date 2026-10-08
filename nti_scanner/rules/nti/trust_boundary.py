"""Trust Boundary Mapping Rule."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class TrustBoundaryRule(BaseRule):
    meta = RuleMeta(
        id="NTI-TRUST-BOUND-001",
        category="Identity",
        severity="high",
        confidence="medium",
        description="Agent crosses network/untrusted boundaries without explicit signature or token validation",
        cwe="CWE-1188",
        remediation="Validate trust domain boundaries and require signed tokens for all remote calls.",
    )

    REMOTE_CALL_MODULES = {"requests", "httpx", "urllib", "aiohttp", "grpc"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_str = ""
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    func_str = f"{node.func.value.id}.{node.func.attr}"
                elif isinstance(node.func, ast.Name):
                    func_str = node.func.id

                if any(m in func_str for m in ["requests.get", "requests.post", "httpx.get", "httpx.post", "aiohttp"]):
                    has_auth = any(kw.arg == "headers" or kw.arg == "auth" for kw in node.keywords)
                    if not has_auth:
                        findings.append(
                            self.make_finding(
                                path,
                                node,
                                f"Remote network call '{func_str}' executed across trust boundary without explicit authentication or signature headers.",
                            )
                        )

        return findings
