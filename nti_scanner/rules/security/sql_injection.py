"""Detect SQL built by interpolating values into a query string."""
import ast
import re
from pathlib import Path
from typing import ClassVar

from nti_scanner.rules.base import BaseRule, Finding, RuleMeta

# A real statement shape, not just the word "from" appearing in prose.
SQL_STATEMENT = re.compile(
    r"^\s*(select\s+.+\s+from\s+|insert\s+into\s+|update\s+\w+\s+set\s+|delete\s+from\s+)",
    re.IGNORECASE | re.DOTALL,
)
# Methods that actually hand a string to a database driver.
EXEC_METHODS: ClassVar[set[str]] = {
    "execute", "executemany", "executescript", "raw", "query", "sql",
    "read_sql", "to_sql", "text",
}


def _base_name(node: ast.AST) -> str:
    cur = node
    while True:
        if isinstance(cur, ast.Name):
            return cur.id
        if isinstance(cur, ast.Attribute):
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        elif isinstance(cur, ast.Subscript):
            cur = cur.value
        else:
            return ""


def _sink_name(node: ast.AST) -> str:
    """Last segment of a call target: `cursor.execute` -> "execute"."""
    if isinstance(node, ast.Attribute):
        return node.attr.lower()
    return _base_name(node).lower()


def _static_sql_part(node: ast.AST) -> bool:
    """True if the node contains a string literal that looks like a SQL statement."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if SQL_STATEMENT.match(sub.value.lstrip("# ")) or SQL_STATEMENT.search(" " + sub.value):
                return True
    return False


def _interpolates(node: ast.AST) -> bool:
    """True if values are spliced into the string (f-string or + concatenation)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    if isinstance(node, ast.Call):
        # "".format(...) / "...%s" % (...)
        return _base_name(node.func) == "format" or bool(node.args)
    return False


class SQLInjectionRule(BaseRule):
    meta = RuleMeta(
        id="SEC-SQL-001",
        category="Security",
        severity="critical",
        confidence="high",
        description="SQL query assembled by interpolating values, then executed",
        cwe="CWE-89",
        remediation="Use parameterized queries with bound parameters.",
    )

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        # Queries are usually built into a variable before being executed, so
        # resolve simple `name = <interpolated sql>` assignments first.
        tainted: dict[str, ast.AST] = {}
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and _static_sql_part(node.value)
                and _interpolates(node.value)
            ):
                tainted[node.targets[0].id] = node.value

        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _sink_name(node.func) not in EXEC_METHODS:
                continue
            for arg in node.args:
                target = arg
                if isinstance(arg, ast.Name) and arg.id in tainted:
                    target = tainted[arg.id]
                if not isinstance(target, (ast.JoinedStr, ast.BinOp, ast.Call)):
                    continue
                if _static_sql_part(target) and _interpolates(target):
                    findings.append(
                        self.make_finding(
                            path,
                            node,
                            f"SQL statement interpolated into {_sink_name(node.func)}() instead of bound parameters.",
                        )
                    )
                    break
        return findings
