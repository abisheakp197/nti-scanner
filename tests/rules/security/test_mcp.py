"""Tests for SEC-MCP-001."""
from nti_scanner.ast_analysis.parser import parse_python_file
from nti_scanner.rules.security.mcp_rules import MCPRule


def _findings(tmp_path, code):
    f = tmp_path / "mod.py"
    f.write_text(code)
    return MCPRule().check(f, parse_python_file(f), [])


def test_mcp_client_without_auth_reported(tmp_path):
    code = "client = MCPClient(server_url=url)\n"
    assert _findings(tmp_path, code)


def test_mcp_client_with_token_not_reported(tmp_path):
    code = 'client = MCPClient(server_url=url, auth_token=tok)\n'
    assert _findings(tmp_path, code) == []


def test_module_mentioning_mcp_is_not_a_finding(tmp_path):
    """Regression: any file containing the word 'mcp' was reported."""
    code = "MCP_SETTINGS = {'enabled': True}\n"
    assert _findings(tmp_path, code) == []
