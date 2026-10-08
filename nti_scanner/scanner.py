"""Core scanning engine with AST parsing and rule execution."""

import ast
from pathlib import Path
from typing import List, Optional

from nti_scanner.models import Finding, ScanResult
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.framework.detector import detect_frameworks
from nti_scanner.rules.registry import RULES


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def scan_directory(
    path: Path,
    min_severity: str = "info",
    excludes: Optional[List[str]] = None,
) -> ScanResult:
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
                result.lines_scanned += len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
            except Exception:
                pass

    result.frameworks = detect_frameworks(all_trees)

    pillar_tracker = {p: 100 for p in ["Identity", "Governance", "Consensus", "Audit", "Persistence"]}

    for f, tree in all_trees.items():
        for rule in RULES:
            try:
                findings = rule.check(f, tree, result.frameworks)
                for finding in findings:
                    if SEVERITY_ORDER.get(finding.severity, 4) <= SEVERITY_ORDER.get(min_severity, 4):
                        result.findings.append(finding)
                        if finding.category in pillar_tracker:
                            penalty = {"critical": 25, "high": 15, "medium": 5, "low": 2, "info": 0}.get(finding.severity, 0)
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
