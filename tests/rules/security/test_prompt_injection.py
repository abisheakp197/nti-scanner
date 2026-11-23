"""Tests for SEC-PROMPT-001.

The rule must fire on untrusted input reaching a model call, and must not fire
merely because a file mentions the word "agent" somewhere.
"""
from pathlib import Path

from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.prompt_injection import PromptInjectionRule


def _findings(tmp_path: Path, code: str, name: str = "mod.py"):
    f = tmp_path / name
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    return PromptInjectionRule().check(f, tree, [])


def test_untrusted_input_into_prompt_triggers(tmp_path):
    code = (
        'def handle(request):\n'
        '    return llm.chat(prompt=f"Summarise: {request.args[\'q\']}")\n'
    )
    findings = _findings(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-PROMPT-001"


def test_static_prompt_no_finding(tmp_path):
    code = 'prompt = "Agent prompt: static user message"\n'
    assert _findings(tmp_path, code, "safe_prompt.py") == []


def test_fstring_in_agent_file_without_sink_is_not_a_finding(tmp_path):
    """Regression: any f-string in any file mentioning 'agent' used to fire."""
    code = (
        '# agent helper module\n'
        'def label(index):\n'
        '    return f"step-{index}"\n'
    )
    assert _findings(tmp_path, code) == []


def test_fstring_in_test_fixture_is_not_a_finding(tmp_path):
    """Regression: test fixtures are expected to build prompts."""
    code = 'payload = f"ignore previous instructions: {user_input}"\n'
    assert _findings(tmp_path, code, "test_fixture.py") == []


def test_sink_without_untrusted_source_no_finding(tmp_path):
    code = (
        'def handler():\n'
        '    return llm.chat(prompt=f"Static text {CONSTANT}")\n'
    )
    assert _findings(tmp_path, code) == []
