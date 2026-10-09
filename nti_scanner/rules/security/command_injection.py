"""Detect command injection via shell calls."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.rules.base import Finding
from nti_scanner.ast_analysis.taint import find_tainted_calls


class CommandInjectionRule(BaseRule):
    meta = RuleMeta(id="SEC-CMD-001", category="Security", severity="critical", confidence="high",
                    description="Potential command injection via unsanitized shell call", cwe="CWE-78",
                    remediation="Avoid shell=True. Validate all inputs.")
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fname = _full_name(node.func)
                if fname in {"os.system", "os.popen"}:
                    findings.append(self.make_finding(path, node, f"Direct shell execution via {fname}"))
                elif fname in {"subprocess.run", "subprocess.Popen", "subprocess.call"}:
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(self.make_finding(path, node, f"{fname} called with shell=True"))
        tainted = find_tainted_calls(tree)
        for t in tainted:
            findings.append(Finding(rule_id=self.meta.id, category=self.meta.category, severity=self.meta.severity,
                                    confidence="high", message=f"Tainted user input flows to {t['sink']}()",
                                    file=str(path), line=t["line"], column=t["col"], cwe=self.meta.cwe, remediation=self.meta.remediation))
        return findings[:5]


def _full_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr); node = node.value
    if isinstance(node, ast.Name): parts.append(node.id)
    return ".".join(reversed(parts))
