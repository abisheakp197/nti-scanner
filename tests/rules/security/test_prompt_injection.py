"""Tests for SEC-PROMPT-001."""
from pathlib import Path

from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.prompt_injection import PromptInjectionRule


def test_fstring_in_prompt_context_triggers_finding(tmp_path: Path) -> None:
    code = 'user_input = "hello"\nprompt = f"Agent prompt: {user_input}"\n'
    f = tmp_path / "prompt.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = PromptInjectionRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-PROMPT-001"


def test_static_prompt_no_finding(tmp_path: Path) -> None:
    code = 'prompt = "Agent prompt: static user message"\n'
    f = tmp_path / "safe_prompt.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = PromptInjectionRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
