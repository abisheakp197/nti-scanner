"""Detect agent tools with dangerous capabilities."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.scanner import Finding


class CapabilityEscalationRule(BaseRule):
    meta = RuleMeta(id="SEC-CAP-001", category="Security", severity="high", confidence="medium",
                    description="Agent tool with destructive capability", cwe="CWE-269",
                    remediation="Require explicit grant and BFT consensus for destructive tools.")
    DANGEROUS_NAMES = {"delete", "drop", "destroy", "terminate", "kill", "execute", "sudo", "admin", "chmod", "chown"}
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = node.name.lower()
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and _name(dec.func) == "tool":
                        if any(d in name for d in self.DANGEROUS_NAMES):
                            findings.append(self.make_finding(path, node, f"Tool '{node.name}' has destructive name."))
        return findings


def _name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    return ""
