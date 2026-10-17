"""Tests for NTI-CAPDIFF-001."""
from pathlib import Path

from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.nti.capability_diff import CapabilityDiffRule


def _check(fixtures_dir: Path, subdir: str) -> list:
    rule = CapabilityDiffRule()
    findings = []
    for f in (fixtures_dir / subdir).rglob("*.py"):
        t = parse_python_file(f)
        if t:
            findings.extend(rule.check(f, t, []))
    return findings


def test_mixed_agent_triggers_capability_diff(fixtures_dir: Path) -> None:
    findings = _check(fixtures_dir, "mixed_agent")
    assert any(f.rule_id == "NTI-CAPDIFF-001" for f in findings)


def test_vulnerable_agent_triggers_capability_diff(fixtures_dir: Path) -> None:
    findings = _check(fixtures_dir, "vulnerable_agent")
    assert any(f.rule_id == "NTI-CAPDIFF-001" for f in findings)


def test_tools_with_grant_capability_no_finding(tmp_path: Path) -> None:
    code = """
from langchain_core.tools import tool

@tool
def search_tool() -> str:
    return "result"

grant_capability("search_tool")
"""
    f = tmp_path / "agent.py"
    f.write_text(code, encoding="utf-8")
    tree = parse_python_file(f)
    assert tree is not None
    rule = CapabilityDiffRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
