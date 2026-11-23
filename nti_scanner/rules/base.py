"""Base class for rules."""
import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    confidence: str
    message: str
    file: str
    line: int
    column: int
    cwe: str | None = None
    remediation: str = ""
    code_snippet: str = ""


@dataclass
class RuleMeta:
    id: str
    category: str
    severity: str
    confidence: str
    description: str
    cwe: str = ""
    remediation: str = ""


class BaseRule:
    meta: RuleMeta
    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        raise NotImplementedError
    def make_finding(self, path: Path, node: ast.AST, message: str, snippet: str = "") -> Finding:
        return Finding(rule_id=self.meta.id, category=self.meta.category, severity=self.meta.severity,
                       confidence=self.meta.confidence, message=message, file=str(path),
                       line=getattr(node, "lineno", 0), column=getattr(node, "col_offset", 0),
                       cwe=self.meta.cwe, remediation=self.meta.remediation, code_snippet=snippet)


def ast_identifiers(tree: ast.AST) -> set[str]:
    """Identifiers actually present in code: names, attributes, and imports.

    Keyword checks run against this instead of raw file text, so a comment or
    docstring that happens to mention a control cannot satisfy the check.
    """
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            found.add(node.id.lower())
        elif isinstance(node, ast.Attribute):
            found.add(node.attr.lower())
        elif isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[-1].lower())
                found.update(part.lower() for part in alias.name.split("."))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.update(part.lower() for part in node.module.split("."))
            for alias in node.names:
                found.add(alias.name.lower())
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.add(node.name.lower())
        elif isinstance(node, ast.keyword) and node.arg:
            found.add(node.arg.lower())
    return found
