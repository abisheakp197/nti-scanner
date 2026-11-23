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

# A conformance gap is worth less than an exploitable defect, and is applied once
# per rule per pillar rather than once per occurrence.
COMPLIANCE_PENALTY = {"critical": 25, "high": 15, "medium": 10, "low": 5, "info": 5}

# Compliance findings are not vulnerabilities; they map onto the NTI-1 pillar
# they describe so the score reflects them while the vuln counts do not.
PILLAR_FOR_RULE = {
    "NTI-PQC-001": "Identity",
    "NTI-IDENT-001": "Identity",
    "NTI-AUDIT-001": "Audit",
    "NTI-GOV-001": "Governance",
    "NTI-CAPDIFF-001": "Governance",
    "NTI-CONS-001": "Consensus",
    "NTI-PERS-001": "Persistence",
}
VULN_SEVERITIES = {"critical", "high", "medium", "low"}

# Findings in test fixtures, examples, and docs describe the harness rather than
# shipped behaviour. They are reported but excluded from the score, the way
# dependency scanners separate dev and production scopes.
NON_PRODUCTION_PARTS = {"tests", "test", "testing", "__tests__", "examples", "example", "docs", "fixtures"}


def finding_scope(path_str: str, root: str | None = None) -> str:
    """Classify a finding relative to the scan root.

    Scope is decided from the path below the root, so scanning a fixture
    directory directly still scores it as the target rather than as test code.
    """
    from pathlib import Path as _Path

    p = _Path(path_str)
    if root:
        try:
            p = p.resolve().relative_to(_Path(root).resolve())
        except ValueError:
            pass
    if set(p.parts) & NON_PRODUCTION_PARTS or p.name.startswith("test_"):
        return "test"
    return "production"


@dataclass
class ScanResult:
    path: str
    frameworks: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    pillar_scores: dict[str, int] = field(default_factory=dict)
    nti1_score: int = 0
    compliance_gaps: list[Finding] = field(default_factory=list)
    _gap_counts: dict[str, int] = field(default_factory=dict)

    def _unique_gaps(self) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for gap in self.compliance_gaps:
            seen.setdefault(gap.rule_id, gap)
        return list(seen.values())
    files_scanned: int = 0
    lines_scanned: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": "0.2.1",
            "path": self.path,
            "frameworks": self.frameworks,
            "nti1_score": self.nti1_score,
            "pillar_scores": self.pillar_scores,
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "vulnerability_counts": {
                sev: sum(
                    1 for f in self.findings
                    if f.severity == sev and finding_scope(f.file, self.path) == "production"
                )
                for sev in ("critical", "high", "medium", "low")
            },
            "test_scope_counts": {
                sev: sum(
                    1 for f in self.findings
                    if f.severity == sev and finding_scope(f.file, self.path) == "test"
                )
                for sev in ("critical", "high", "medium", "low")
            },
            "compliance_gaps": [
                {
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "severity": f.severity,
                    "message": f.message,
                    "file": f.file,
                    "line": f.line,
                    "remediation": f.remediation,
                    "occurrences": self._gap_counts.get(f.rule_id, 1),
                }
                for f in self._unique_gaps()
            ],
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
                    "scope": finding_scope(f.file, self.path),
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
    applied: set[tuple[str, str]] = set()
    for f, tree in all_trees.items():
        for rule in RULES:
            try:
                findings = rule.check(f, tree, result.frameworks)
                _apply_findings(findings, min_severity, result, pillar_tracker, applied)
            except (OSError, SyntaxError, ValueError, KeyError):
                continue
    result.pillar_scores = pillar_tracker
    if pillar_tracker:
        result.nti1_score = int(sum(pillar_tracker.values()) / len(pillar_tracker))
    return result


def _apply_findings(
    findings: list[Finding],
    min_severity: str,
    result: ScanResult,
    pillar_tracker: dict[str, int],
    applied: set[tuple[str, str]],
) -> None:
    for finding in findings:
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[min_severity]:
            continue
        if finding.category == "Compliance":
            result.compliance_gaps.append(finding)
            result._gap_counts[finding.rule_id] = result._gap_counts.get(finding.rule_id, 0) + 1
            pillar = PILLAR_FOR_RULE.get(finding.rule_id)
            is_gap = True
        else:
            result.findings.append(finding)
            pillar = finding.category
            is_gap = False
        if pillar not in pillar_tracker:
            continue
        if finding_scope(finding.file, result.path) != "production":
            continue

        # Penalise each distinct rule once per pillar. Counting every occurrence
        # let a single noisy rule zero an entire pillar.
        key = (pillar, finding.rule_id)
        if key in applied:
            continue
        applied.add(key)
        table = COMPLIANCE_PENALTY if is_gap else PENALTY_MAP
        penalty = table.get(finding.severity, 0)
        pillar_tracker[pillar] = max(0, pillar_tracker[pillar] - penalty)


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
