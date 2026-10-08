"""Data models for nti-scanner."""

from dataclasses import dataclass, field
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
class ScanResult:
    path: str
    frameworks: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    pillar_scores: dict = field(default_factory=dict)
    nti1_score: int = 0
    files_scanned: int = 0
    lines_scanned: int = 0

    def to_dict(self):
        return {
            "version": "0.1.0",
            "path": self.path,
            "frameworks": self.frameworks,
            "nti1_score": self.nti1_score,
            "pillar_scores": self.pillar_scores,
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "message": f.message,
                    "file": f.file,
                    "line": f.line,
                    "column": f.column,
                    "cwe": f.cwe,
                    "remediation": f.remediation,
                }
                for f in self.findings
            ],
        }
