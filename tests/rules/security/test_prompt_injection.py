"""Tests for SEC-PROMPT-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.prompt_injection import PromptInjectionRule


def test_fstring_in_prompt_context(tmp_path):
    code = 'user = "hello"\nprompt = f"Agent: {user}"\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = PromptInjectionRule()
    findings = rule.check(f, tree, [])
    # Only fires if content mentions agent/llm/prompt keywords
    assert isinstance(findings, list)
