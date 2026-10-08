"""NTI-1 Pillar 5: Persistence."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class PersistenceRule(BaseRule):
    meta = RuleMeta(
        id="NTI-PERSIST-001",
        category="Persistence",
        severity="medium",
        confidence="medium",
        description="Agent state or memory is stored without encryption or integrity checks",
        cwe="CWE-922",
        remediation="Encrypt persistent memory and state vector databases at rest with authenticated encryption.",
    )

    PERSISTENCE_KEYWORDS = {"pickle", "shelve", "sqlite3", "chromadb", "pinecone", "qdrant", "weaviate", "redis"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self.PERSISTENCE_KEYWORDS:
                        findings.append(
                            self.make_finding(
                                path,
                                node,
                                f"Agent imports unencrypted/raw persistence mechanism: {alias.name}.",
                            )
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in self.PERSISTENCE_KEYWORDS:
                    findings.append(
                        self.make_finding(
                            path,
                            node,
                            f"Agent imports unencrypted/raw persistence module: {node.module}.",
                        )
                    )

        return findings
