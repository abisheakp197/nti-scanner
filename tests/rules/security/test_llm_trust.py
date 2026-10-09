"""Tests for SEC-LLM-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.llm_trust import LLMTrustRule


def test_llm_output_to_eval_detected(tmp_path):
    code = 'out = llm.invoke("x")\neval(out)\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = LLMTrustRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-LLM-001" for x in findings)
