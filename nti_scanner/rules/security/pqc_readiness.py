"""PQC Readiness Rule."""

import ast
from pathlib import Path
from typing import List

from nti_scanner.models import Finding
from nti_scanner.rules.base import BaseRule, RuleMeta


class PQCReadinessRule(BaseRule):
    meta = RuleMeta(
        id="SEC-PQC-001",
        category="Security",
        severity="medium",
        confidence="high",
        description="Classical non-quantum-resistant cryptographic algorithms used in agent identity or state signing",
        cwe="CWE-327",
        remediation="Upgrade classical RSA/ECC cryptography to Post-Quantum Cryptography (PQC) standards such as ML-DSA (Dilithium) or ML-KEM (Kyber).",
    )

    CLASSICAL_CRYPTO = {"rsa", "ecdsa", "dsa", "crypto.cipher", "cryptography.hazmat.primitives.asymmetric.rsa"}

    def check(self, path: Path, tree: ast.AST, frameworks: List[str]) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(c in alias.name.lower() for c in ["rsa", "ecdsa"]):
                        findings.append(
                            self.make_finding(
                                path,
                                node,
                                f"Classical asymmetric crypto module '{alias.name}' detected; recommend migrating to Post-Quantum Cryptography (PQC).",
                            )
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module and any(c in node.module.lower() for c in ["rsa", "ecdsa", "asymmetric"]):
                    findings.append(
                        self.make_finding(
                            path,
                            node,
                            f"Classical asymmetric crypto module '{node.module}' detected; recommend migrating to Post-Quantum Cryptography (PQC).",
                        )
                    )

        return findings
