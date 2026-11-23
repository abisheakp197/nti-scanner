"""Detect unsanitized user input flowing into a prompt sent to a model."""
import ast
from pathlib import Path
from typing import ClassVar

from nti_scanner.rules.base import BaseRule, Finding, RuleMeta

# Names that indicate a value originates outside the process (HTTP bodies,
# request args, LLM output, environment, CLI input).
UNTRUSTED_SOURCES: ClassVar[set[str]] = {
    "request", "req", "data", "body", "payload", "params", "kwargs", "args",
    "input", "user_input", "user_text", "user_message", "message",
    "content", "form", "json", "query", "text", "raw", "untrusted",
    "response", "completion", "llm_output", "tool_output", "observation",
}
# Function names that actually reach a model or execute a tool.
SINK_CALLS: ClassVar[set[str]] = {
    "chat", "completion", "create", "invoke", "run", "generate", "predict",
    "call", "acompletion", "achat", "astream", "stream", "send", "execute",
    "prompt", "ask", "query", "format_prompt", "add_message", "append",
}
# Parameters that name a prompt-like slot on the call.
PROMPT_PARAMS: ClassVar[set[str]] = {
    "prompt", "content", "messages", "system", "user", "instruction",
    "text", "input", "query", "message",
}


def _base_name(node: ast.AST) -> str:
    """Resolve `a.b.c` / `a[0]` / `f()` to the leftmost identifier."""
    cur = node
    while True:
        if isinstance(cur, ast.Name):
            return cur.id
        if isinstance(cur, ast.Attribute):
            cur = cur.value
        elif isinstance(cur, ast.Subscript):
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        else:
            return ""


def _sink_name(node: ast.AST) -> str:
    """Last segment of a call target: `llm.chat` -> "chat", `run` -> "run"."""
    if isinstance(node, ast.Attribute):
        return node.attr.lower()
    return _base_name(node).lower()


def _is_untrusted(node: ast.AST) -> bool:
    name = _base_name(node).lower()
    return name in UNTRUSTED_SOURCES or name.endswith("_input") or name.endswith("_text")


def _contains_untrusted(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, (ast.Name, ast.Attribute, ast.Subscript)) and _is_untrusted(sub):
            return True
    return False


class PromptInjectionRule(BaseRule):
    meta = RuleMeta(
        id="SEC-PROMPT-001",
        category="Security",
        severity="high",
        confidence="medium",
        description="Untrusted input interpolated into a prompt or tool call",
        cwe="CWE-1336",
        remediation="Pass untrusted text as a separate message/tool argument rather than interpolating it.",
    )

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        # Test code asserts on fixtures; interpolating literals there is the point.
        parts = set(path.parts)
        if parts & {"tests", "test", "testing", "__tests__"} or path.name.startswith("test_") or path.name.endswith("_test.py"):
            return []

        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _sink_name(node.func) not in SINK_CALLS:
                continue

            prompt_like = False
            user_value = False
            for kw in node.keywords:
                if kw.arg in PROMPT_PARAMS and _contains_untrusted(kw.value):
                    prompt_like = user_value = True
            for arg in node.args:
                if isinstance(arg, (ast.JoinedStr, ast.BinOp)) and _contains_untrusted(arg):
                    # An f-string / concatenation built from untrusted input, handed
                    # straight to a model-facing call.
                    prompt_like = user_value = True
                elif isinstance(arg, ast.JoinedStr) and any(
                    isinstance(v, ast.FormattedValue) for v in arg.values
                ):
                    if any(kw.arg in PROMPT_PARAMS for kw in node.keywords):
                        prompt_like = user_value = True

            if prompt_like and user_value:
                findings.append(
                    self.make_finding(
                        path,
                        node,
                        f"Untrusted value interpolated into {_sink_name(node.func) or 'call'}() prompt argument.",
                    )
                )
        return findings
