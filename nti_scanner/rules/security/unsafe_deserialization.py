"""Unsafe Deserialization Rule."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class UnsafeDeserializationRule(BaseRule):
    meta = RuleMeta(
        id="SEC-DESER-001",
        category="Security",
        severity="critical",
        confidence="high",
        description="Unsafe deserialization of arbitrary data (e.g., pickle, yaml.unsafe_load)",
        cwe="CWE-502",
        remediation="Use safe serialization formats like JSON or yaml.safe_load.",
    )

    UNSAFE_DESER_FUNCS = {"pickle.loads", "pickle.load", "marshal.loads", "shelve.open"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    func_name = f"{node.func.value.id}.{node.func.attr}"
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if func_name in self.UNSAFE_DESER_FUNCS:
                    findings.append(
                        self.make_finding(
                            path,
                            node,
                            f"Call to unsafe deserialization function '{func_name}'.",
                        )
                    )
                elif func_name == "yaml.load":
                    has_safe_loader = False
                    for kw in node.keywords:
                        if kw.arg == "Loader" and "Safe" in ast.dump(kw.value):
                            has_safe_loader = True
                    if not has_safe_loader:
                        findings.append(
                            self.make_finding(
                                path,
                                node,
                                "yaml.load called without SafeLoader risks arbitrary code execution.",
                            )
                        )

        return findings
