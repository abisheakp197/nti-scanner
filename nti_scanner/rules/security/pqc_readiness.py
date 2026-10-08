"""Detect classical crypto that quantum computers will break."""
import ast
from pathlib import Path
from typing import List
from nti_scanner.rules.base import BaseRule, RuleMeta
from nti_scanner.scanner import Finding


class PQCReadinessRule(BaseRule):
    meta = RuleMeta(id="SEC-PQC-001", category="Identity", severity="high", confidence="high",
                    description="Quantum-vulnerable cryptography (RSA/ECDSA/DH)", cwe="CWE-327",
                    remediation="Migrate to Dilithium5/Kyber1024.")
    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = []
                if isinstance(node, ast.Import): names = [n.name for n in node.names]
                else: names = [node.module or ""]
                for name in names:
                    if any(p in str(name).lower() for p in ["rsa", "ecdsa", "cryptography.hazmat.primitives.asymmetric"]):
                        findings.append(self.make_finding(path, node, f"Quantum-vulnerable crypto imported: {name}."))
                        break
        return findings[:3]
