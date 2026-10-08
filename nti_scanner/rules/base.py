"""Base class for rules."""
import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


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
    cwe: Optional[str] = None
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
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        raise NotImplementedError
    def make_finding(self, path: Path, node: ast.AST, message: str, snippet: str = "") -> Finding:
        return Finding(rule_id=self.meta.id, category=self.meta.category, severity=self.meta.severity,
                       confidence=self.meta.confidence, message=message, file=str(path),
                       line=getattr(node, "lineno", 0), column=getattr(node, "col_offset", 0),
                       cwe=self.meta.cwe, remediation=self.meta.remediation, code_snippet=snippet)
