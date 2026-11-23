"""Rules for Model Context Protocol (MCP) security."""
import ast
from pathlib import Path
from typing import ClassVar

from nti_scanner.rules.base import BaseRule, Finding, RuleMeta, ast_identifiers


class MCPRule(BaseRule):
    meta = RuleMeta(id="SEC-MCP-001", category="Security", severity="high", confidence="medium",
                    description="MCP server or client without authentication", cwe="CWE-287",
                    remediation="Use NTI signed capability tokens for all MCP tool calls.")
    MCP_CLIENT_NAMES: ClassVar[set[str]] = {
        "mcpclient", "fastmcp", "mcpserver", "mcpsession", "stdio_client",
        "sse_client", "streamablehttp_client",
    }
    AUTH_KWARGS: ClassVar[set[str]] = {
        "auth", "auth_token", "token", "api_key", "bearer_token", "credentials",
        "headers", "verify", "signature", "capability_token",
    }

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node.func)
            if name not in self.MCP_CLIENT_NAMES:
                continue
            supplied = {kw.arg.lower() for kw in node.keywords if kw.arg}
            if supplied & self.AUTH_KWARGS:
                continue
            return [self.make_finding(
                path, node,
                f"MCP client '{name}' constructed without authentication parameters.",
            )]
        return []


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr.lower()
    if isinstance(node, ast.Name):
        return node.id.lower()
    return ""
