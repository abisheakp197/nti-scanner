"""Rules for Model Context Protocol (MCP) security."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.rules.base import Finding


class MCPRule(BaseRule):
    meta = RuleMeta(id="SEC-MCP-001", category="Security", severity="high", confidence="medium",
                    description="MCP server or client without authentication", cwe="CWE-287",
                    remediation="Use NTI signed capability tokens for all MCP tool calls.")
    MCP_INDICATORS = {"mcp", "modelcontext", "mcpclient", "mcpserver", "fastmcp"}
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        content = path.read_text(errors="ignore").lower()
        if not any(kw in content for kw in self.MCP_INDICATORS): return []
        has_auth = any(kw in content for kw in ["auth", "token", "signature", "verify", "nti"])
        if not has_auth:
            node = next(iter(ast.walk(tree)), tree)
            return [self.make_finding(path, node, "MCP integration without authentication.")]
        return []
