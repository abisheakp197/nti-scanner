"""Command Injection Rule."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.ast_analysis.taint import find_tainted_calls
from nti_scanner.rules.base import BaseRule, RuleMeta


class CommandInjectionRule(BaseRule):
    meta = RuleMeta(
        id="SEC-CMD-001",
        category="Security",
        severity="critical",
        confidence="high",
        description="OS command execution with potentially tainted or dynamic input",
        cwe="CWE-78",
        remediation="Avoid shell execution or pass arguments as a list without shell=True.",
    )

    UNSAFE_FUNCS = {"os.system", "os.popen", "subprocess.Popen", "subprocess.run", "subprocess.call"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        tainted_calls = find_tainted_calls(tree)
        for call in tainted_calls:
            if call["sink"] in self.UNSAFE_FUNCS:
                findings.append(
                    Finding(
                        rule_id=self.meta.id,
                        category=self.meta.category,
                        severity=self.meta.severity,
                        confidence=self.meta.confidence,
                        message=f"Tainted variable '{call['source']}' passed directly to OS command sink '{call['sink']}'.",
                        file=str(path),
                        line=call["line"],
                        column=call["col"],
                        cwe=self.meta.cwe,
                        remediation=self.meta.remediation,
                    )
                )

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    func_name = f"{node.func.value.id}.{node.func.attr}"
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if func_name in self.UNSAFE_FUNCS:
                    # Check shell=True
                    has_shell_true = any(
                        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                        for kw in node.keywords
                    )
                    # Check os.system / os.popen with dynamic or variable argument
                    is_os_cmd = func_name in {"os.system", "os.popen"}
                    has_dynamic_arg = False
                    if node.args:
                        first_arg = node.args[0]
                        if not isinstance(first_arg, ast.Constant):
                            has_dynamic_arg = True

                    if has_shell_true or (is_os_cmd and has_dynamic_arg):
                        findings.append(
                            self.make_finding(
                                path,
                                node,
                                f"Command execution '{func_name}' called with dynamic arguments or shell=True.",
                            )
                        )

        return findings
