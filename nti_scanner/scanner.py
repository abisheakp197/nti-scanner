"""Core scanning engine."""
import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.framework.detector import detect_frameworks
from nti_scanner.rules.base import Finding
from nti_scanner.rules.registry import RULES

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
PENALTY_MAP = {"critical": 25, "high": 15, "medium": 5, "low": 2, "info": 0}


@dataclass
class ScanResult:
    path: str
    frameworks: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    pillar_scores: dict[str, int] = field(default_factory=dict)
    nti1_score: int = 0
    files_scanned: int = 0
    lines_scanned: int = 0

    def to_dict(self) -> dict[str, Any]:
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


def scan_directory(path: Path, min_severity: str = "info", excludes: list[str] | None = None) -> ScanResult:
    excludes = excludes or []
    result = ScanResult(path=str(path))
    files = _collect_python_files(path, excludes)
    result.files_scanned = len(files)
    all_trees: dict[Path, ast.AST] = {}
    for f in files:
        tree = parse_python_file(f)
        if tree is not None:
            all_trees[f] = tree
            try:
                result.lines_scanned += len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
            except (OSError, UnicodeDecodeError):
                pass
    result.frameworks = detect_frameworks(all_trees)
    pillar_tracker = {p: 100 for p in ["Identity", "Governance", "Consensus", "Audit", "Persistence", "Security"]}
    for f, tree in all_trees.items():
        for rule in RULES:
            try:
                findings = rule.check(f, tree, result.frameworks)
                _apply_findings(findings, min_severity, result, pillar_tracker)
            except (OSError, SyntaxError, ValueError, KeyError):
                continue
    result.pillar_scores = pillar_tracker
    if pillar_tracker:
        result.nti1_score = int(sum(pillar_tracker.values()) / len(pillar_tracker))
    return result


def _apply_findings(findings: list[Finding], min_severity: str, result: ScanResult, pillar_tracker: dict[str, int]) -> None:
    for finding in findings:
        if SEVERITY_ORDER[finding.severity] <= SEVERITY_ORDER[min_severity]:
            result.findings.append(finding)
            if finding.category in pillar_tracker:
                penalty = PENALTY_MAP.get(finding.severity, 0)
                pillar_tracker[finding.category] = max(0, pillar_tracker[finding.category] - penalty)


def _collect_python_files(root: Path, excludes: list[str]) -> list[Path]:
    files: list[Path] = []
    if not root.exists():
        return files
    if root.is_file():
        if root.suffix == ".py":
            files.append(root)
        return files
    for f in root.rglob("*.py"):
        try:
            rel = f.relative_to(root)
        except ValueError:
            rel = f
        if any(part.startswith(".") for part in rel.parts):
            continue
        str_f = str(f)
        if any(ex in str_f for ex in excludes):
            continue
        if "site-packages" in str_f or "node_modules" in str_f or "__pycache__" in str_f:
            continue
        files.append(f)
    return files
