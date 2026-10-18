"""Detect unsafe deserialization."""
import ast
from pathlib import Path
from typing import ClassVar

from nti_scanner.rules.base import BaseRule, Finding, RuleMeta


class UnsafeDeserializationRule(BaseRule):
    meta = RuleMeta(id="SEC-DESER-001", category="Security", severity="critical", confidence="high",
                    description="Unsafe deserialization (pickle, yaml.load)", cwe="CWE-502",
                    remediation="Use json instead of pickle. Use safe_load for YAML.")
    UNSAFE: ClassVar[set[str]] = {"pickle.load", "pickle.loads", "yaml.load", "dill.loads", "marshal.loads"}

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fname = _full_name(node.func)
                if fname in self.UNSAFE:
                    findings.append(self.make_finding(path, node, f"Unsafe deserialization via {fname}()"))
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
