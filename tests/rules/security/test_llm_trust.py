"""Tests for SEC-LLM-001."""
from pathlib import Path

from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.llm_trust import LLMTrustRule


def test_llm_output_to_eval_detected(tmp_path: Path) -> None:
    code = 'out = llm.invoke("x")\neval(out)\n'
    f = tmp_path / "test.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = LLMTrustRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-LLM-001" for x in findings)


def test_safe_llm_usage_no_finding(tmp_path: Path) -> None:
    code = 'out = llm.invoke("x")\nprint(out)\n'
    f = tmp_path / "test.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = LLMTrustRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
