"""Detect SSRF in HTTP requests."""
import ast
from pathlib import Path
from typing import ClassVar

from nti_scanner.rules.base import BaseRule, Finding, RuleMeta


class SSRRule(BaseRule):
    meta = RuleMeta(id="SEC-SSRF-001", category="Security", severity="high", confidence="medium",
                    description="Potential SSRF via dynamic URL in HTTP request", cwe="CWE-918",
                    remediation="Validate and allowlist URLs.")
    HTTP_CALLS: ClassVar[set[str]] = {"requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen"}

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fname = _full_name(node.func)
                if fname in self.HTTP_CALLS and node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, (ast.Name, ast.Attribute, ast.Subscript, ast.BinOp)):
                        findings.append(self.make_finding(path, node, f"Dynamic URL passed to {fname}()"))
        return findings[:3]


def _full_name(node: ast.AST) -> str:
    parts: list[str] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))
