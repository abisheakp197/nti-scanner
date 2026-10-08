"""Core scanning engine."""
import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.framework.detector import detect_frameworks
from nti_scanner.rules.base import Finding
from nti_scanner.rules.registry import RULES


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


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
        return {"version": "0.1.0", "path": self.path, "frameworks": self.frameworks,
                "nti1_score": self.nti1_score, "pillar_scores": self.pillar_scores,
                "files_scanned": self.files_scanned, "lines_scanned": self.lines_scanned,
                "findings": [{"rule_id": f.rule_id, "category": f.category, "severity": f.severity,
                              "confidence": f.confidence, "message": f.message, "file": f.file,
                              "line": f.line, "column": f.column, "cwe": f.cwe,
                              "remediation": f.remediation} for f in self.findings]}


def scan_directory(path: Path, min_severity: str = "info", excludes: Optional[List[str]] = None) -> ScanResult:
    excludes = excludes or []
    result = ScanResult(path=str(path))
    files = _collect_python_files(path, excludes)
    result.files_scanned = len(files)
    all_trees = {}
    for f in files:
        tree = parse_python_file(f)
        if tree is not None:
            all_trees[f] = tree
            try:
                result.lines_scanned += len(f.read_text(errors="ignore").splitlines())
            except Exception:
                pass
    result.frameworks = detect_frameworks(all_trees)
    pillar_tracker = {p: 100 for p in ["Identity", "Governance", "Consensus", "Audit", "Persistence"]}
    for f, tree in all_trees.items():
        for rule in RULES:
            try:
                findings = rule.check(f, tree, result.frameworks)
                for finding in findings:
                    if SEVERITY_ORDER[finding.severity] <= SEVERITY_ORDER[min_severity]:
                        result.findings.append(finding)
                        if finding.category in pillar_tracker:
                            penalty = {"critical": 25, "high": 15, "medium": 5, "low": 2, "info": 0}[finding.severity]
                            pillar_tracker[finding.category] = max(0, pillar_tracker[finding.category] - penalty)
            except Exception:
                continue
    result.pillar_scores = pillar_tracker
    if pillar_tracker:
        result.nti1_score = int(sum(pillar_tracker.values()) / len(pillar_tracker))
    return result


def _collect_python_files(root: Path, excludes: List[str]) -> List[Path]:
    files = []
    for f in root.rglob("*.py"):
        if any(part.startswith(".") for part in f.parts):
            continue
        if any(ex in str(f) for ex in excludes):
            continue
        if "site-packages" in str(f) or "node_modules" in str(f):
            continue
        files.append(f)
    return files
