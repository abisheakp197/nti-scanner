"""Base class for rules."""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List

from nti_scanner.models import Finding


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
        return Finding(
            rule_id=self.meta.id,
            category=self.meta.category,
            severity=self.meta.severity,
            confidence=self.meta.confidence,
            message=message,
            file=str(path),
            line=getattr(node, "lineno", 0),
            column=getattr(node, "col_offset", 0),
            cwe=self.meta.cwe,
            remediation=self.meta.remediation,
            code_snippet=snippet,
        )
