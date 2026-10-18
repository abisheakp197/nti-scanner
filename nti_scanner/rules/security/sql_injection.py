"""Detect SQL injection in agent tools."""
import ast
from pathlib import Path
from typing import ClassVar

from nti_scanner.rules.base import BaseRule, Finding, RuleMeta


class SQLInjectionRule(BaseRule):
    meta = RuleMeta(id="SEC-SQL-001", category="Security", severity="critical", confidence="high",
                    description="SQL query built via string concatenation or f-string", cwe="CWE-89",
                    remediation="Use parameterized queries.")
    SQL_KEYWORDS: ClassVar[set[str]] = {"select", "insert", "update", "delete", "where", "from"}

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                for v in ast.walk(node):
                    if isinstance(v, ast.Constant) and isinstance(v.value, str) and any(kw in v.value.lower() for kw in self.SQL_KEYWORDS):
                        findings.append(self.make_finding(path, node, "f-string contains SQL keywords."))
                        break
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str) and any(kw in node.left.value.lower() for kw in self.SQL_KEYWORDS):
                findings.append(self.make_finding(path, node, "SQL string concatenation detected."))
        return findings[:3]
