"""Path Traversal Rule."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class PathTraversalRule(BaseRule):
    meta = RuleMeta(
        id="SEC-PATH-001",
        category="Security",
        severity="high",
        confidence="medium",
        description="Unsanitized file path construction allows arbitrary file access",
        cwe="CWE-22",
        remediation="Validate user-supplied file paths using Path.resolve() and verify they remain inside target root directory.",
    )

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name == "open":
                    for arg in node.args:
                        if isinstance(arg, ast.BinOp) or isinstance(arg, ast.JoinedStr):
                            findings.append(
                                self.make_finding(
                                    path,
                                    node,
                                    "Dynamic path concatenation inside open() call may allow path traversal.",
                                )
                            )

        return findings
