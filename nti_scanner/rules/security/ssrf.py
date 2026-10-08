"""Detect SSRF in HTTP requests."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.scanner import Finding


class SSRRule(BaseRule):
    meta = RuleMeta(id="SEC-SSRF-001", category="Security", severity="high", confidence="medium",
                    description="Potential SSRF via dynamic URL in HTTP request", cwe="CWE-918",
                    remediation="Validate and allowlist URLs.")
    HTTP_CALLS = {"requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen"}
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fname = _full_name(node.func)
                if fname in self.HTTP_CALLS and node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, (ast.Name, ast.Attribute, ast.Subscript, ast.BinOp)):
                        findings.append(self.make_finding(path, node, f"Dynamic URL passed to {fname}()"))
        return findings[:3]


def _full_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr); node = node.value
    if isinstance(node, ast.Name): parts.append(node.id)
    return ".".join(reversed(parts))
