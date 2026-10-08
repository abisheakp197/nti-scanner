"""Detect unsanitized user input in agent prompts."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.scanner import Finding


class PromptInjectionRule(BaseRule):
    meta = RuleMeta(id="SEC-PROMPT-001", category="Security", severity="high", confidence="medium",
                    description="Unsanitized user input concatenated into agent prompt", cwe="CWE-1336",
                    remediation="Use structured prompt templates instead of f-strings.")
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        content_lower = path.read_text(errors="ignore").lower()
        if not any(kw in content_lower for kw in ["agent", "llm", "prompt"]): return []
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                for value in node.values:
                    if isinstance(value, ast.FormattedValue):
                        if isinstance(value.value, (ast.Name, ast.Attribute, ast.Subscript)):
                            findings.append(self.make_finding(path, node, "f-string used in prompt context."))
                            break
        return findings[:3]
