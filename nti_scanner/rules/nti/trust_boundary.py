"""NTI-unique: Trace trust boundary crossings."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.scanner import Finding


class TrustBoundaryRule(BaseRule):
    meta = RuleMeta(id="NTI-TRUST-001", category="Security", severity="high", confidence="high",
                    description="Trust boundary crossing without NTI verification", cwe="CWE-1426",
                    remediation="Wrap the boundary crossing with an NTI callback.")
    PRIVILEGED_SINKS = {"eval", "exec", "compile", "__import__", "open"}
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        llm_outputs = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    fname = _name(node.value.func)
                    if fname in {"invoke", "run", "predict", "generate", "chat", "completion"}:
                        for t in node.targets:
                            if isinstance(t, ast.Name): llm_outputs.add(t.id)
            if isinstance(node, ast.Call):
                fname = _name(node.func)
                if fname in self.PRIVILEGED_SINKS:
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in llm_outputs:
                            findings.append(self.make_finding(path, node, f"Trust boundary crossing: LLM output '{arg.id}' flows to {fname}()."))
        return findings[:3]


def _name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    return ""
