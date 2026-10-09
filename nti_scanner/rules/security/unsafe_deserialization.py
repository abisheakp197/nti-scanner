"""Detect unsafe deserialization."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.rules.base import Finding


class UnsafeDeserializationRule(BaseRule):
    meta = RuleMeta(id="SEC-DESER-001", category="Security", severity="critical", confidence="high",
                    description="Unsafe deserialization (pickle, yaml.load)", cwe="CWE-502",
                    remediation="Use json instead of pickle. Use safe_load for YAML.")
    UNSAFE = {"pickle.load", "pickle.loads", "yaml.load", "dill.loads", "marshal.loads"}
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fname = _full_name(node.func)
                if fname in self.UNSAFE:
                    findings.append(self.make_finding(path, node, f"Unsafe deserialization via {fname}()"))
        return findings[:3]


def _full_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr); node = node.value
    if isinstance(node, ast.Name): parts.append(node.id)
    return ".".join(reversed(parts))
