"""MCP Rules."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class MCPRule(BaseRule):
    meta = RuleMeta(
        id="SEC-MCP-001",
        category="Security",
        severity="high",
        confidence="medium",
        description="Model Context Protocol (MCP) server or client lacks authentication or input validation",
        cwe="CWE-284",
        remediation="Enforce authentication and input schema validation on MCP tool/resource endpoints.",
    )

    MCP_KEYWORDS = {"mcp", "model_context_protocol", "mcp_server", "mcp_client"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        is_mcp = "Model Context Protocol (MCP)" in frameworks

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "mcp" in alias.name.lower():
                        is_mcp = True
            elif isinstance(node, ast.ImportFrom):
                if node.module and "mcp" in node.module.lower():
                    is_mcp = True

        if is_mcp:
            has_auth = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and any(k in node.id.lower() for k in ["auth", "token", "key", "api_key"]):
                    has_auth = True

            if not has_auth:
                first_node = next(ast.walk(tree), None)
                if first_node:
                    findings.append(
                        self.make_finding(
                            path,
                            first_node,
                            "MCP implementation lacks authentication or token validation controls.",
                        )
                    )

        return findings
