"""SQL Injection Rule."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class SQLInjectionRule(BaseRule):
    meta = RuleMeta(
        id="SEC-SQL-001",
        category="Security",
        severity="critical",
        confidence="high",
        description="SQL query constructed using dynamic string formatting",
        cwe="CWE-89",
        remediation="Use parameterized queries with placeholder bindings instead of raw string interpolation.",
    )

    SQL_METHODS = {"execute", "executemany", "raw_query"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in self.SQL_METHODS:
                    if node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                            findings.append(
                                self.make_finding(
                                    path,
                                    node,
                                    f"SQL query in '{node.func.attr}' constructed via dynamic string formatting.",
                                )
                            )

        return findings
