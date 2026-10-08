"""Detect blind trust in LLM output."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.scanner import Finding


class LLMTrustRule(BaseRule):
    meta = RuleMeta(id="SEC-LLM-001", category="Security", severity="high", confidence="medium",
                    description="LLM output used as code or command without validation", cwe="CWE-1426",
                    remediation="Never eval() or exec() LLM output.")
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        llm_vars = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    fname = _name(node.value.func)
                    if any(k in fname for k in {"invoke", "run", "predict", "generate", "chat"}):
                        for t in node.targets:
                            if isinstance(t, ast.Name): llm_vars.add(t.id)
            if isinstance(node, ast.Call):
                fname = _name(node.func)
                if fname in {"eval", "exec", "compile"}:
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in llm_vars:
                            findings.append(self.make_finding(path, node, f"LLM output passed to {fname}()"))
        return findings[:3]


def _name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    return ""
