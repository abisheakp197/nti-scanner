"""Prompt Injection Rule."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class PromptInjectionRule(BaseRule):
    meta = RuleMeta(
        id="SEC-PROMPT-001",
        category="Security",
        severity="critical",
        confidence="high",
        description="Untrusted user input formatted directly into LLM prompt template",
        cwe="CWE-20",
        remediation="Use structured prompt templates with variable binding instead of string concatenation/f-strings.",
    )

    PROMPT_VAR_NAMES = {"prompt", "system_prompt", "user_prompt", "query", "instruction", "input_text"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):  # f-string
                for parent in ast.walk(tree):
                    if isinstance(parent, ast.Assign):
                        for target in parent.targets:
                            if isinstance(target, ast.Name) and target.id.lower() in self.PROMPT_VAR_NAMES:
                                if parent.value == node:
                                    findings.append(
                                        self.make_finding(
                                            path,
                                            node,
                                            f"Direct f-string formatting into prompt variable '{target.id}' risks prompt injection.",
                                        )
                                    )
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):  # % formatting
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                    if any(p in node.left.value.lower() for p in ["you are", "system:", "human:", "assistant:"]):
                        findings.append(
                            self.make_finding(
                                path,
                                node,
                                "Direct '%' formatting into system/human prompt string risks prompt injection.",
                            )
                        )

        return findings
