"""Tests for SEC-MCP-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.mcp_rules import MCPRule


def test_mcp_without_auth(tmp_path):
    code = 'from mcp import MCPServer\nserver = MCPServer()\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = MCPRule()
    findings = rule.check(f, tree, [])
    assert any(x.rule_id == "SEC-MCP-001" for x in findings)


def test_mcp_with_auth_no_finding(tmp_path):
    code = 'from mcp import MCPServer\ntoken = "secret"\nverify(token)\n'
    f = tmp_path / "test.py"
    f.write_text(code)
    tree = parse_python_file(f)
    rule = MCPRule()
    findings = rule.check(f, tree, [])
    assert len(findings) == 0
