"""Report classical-crypto usage as an architecture gap, not a per-file vuln.

Absence of post-quantum cryptography is a property of a codebase, not of an
individual file. Emitting one high-severity "vulnerability" per file both
inflated counts and mis-described the risk, so this rule now reports a single
compliance gap per repository (deduplicated by the scanner).
"""
import ast
from pathlib import Path
from typing import ClassVar
from nti_scanner.rules.base import BaseRule, Finding, RuleMeta

CLASSICAL_CRYPTO: ClassVar[set[str]] = {
    "rsa", "ecdsa", "dsa", "pycryptodome", "cryptodome",
}
# Kyber is a KEM and Dilithium a signature scheme, so "migrate RSA to Kyber1024"
# is not a drop-in swap. Name the actual replacement per primitive.
REPLACEMENTS: ClassVar[dict[str, str]] = {
    "rsa": "ML-KEM-1024 (FIPS 203) for encryption and ML-DSA-87 (FIPS 204) for signatures",
    "ecdsa": "ML-DSA-87 (FIPS 204)",
    "dsa": "ML-DSA-87 (FIPS 204)",
}


class PQCReadinessRule(BaseRule):
    meta = RuleMeta(
        id="NTI-PQC-001",
        category="Compliance",
        severity="info",
        confidence="high",
        description="Classical (quantum-vulnerable) cryptography in use",
        cwe="",
        remediation="Plan migration to NIST PQC primitives (ML-KEM-1024, ML-DSA-87).",
    )

    def check(self, path: Path, tree: ast.AST, frameworks: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            if isinstance(node, ast.Import):
                names = [n.name for n in node.names]
            else:
                names = [node.module or ""] + [n.name for n in node.names]
            for name in names:
                # Match whole dotted segments: "conversation" contains "rsa"
                # as a substring but is not a crypto import.
                segments = {part.lower() for part in str(name).split(".")}
                hit = next((c for c in CLASSICAL_CRYPTO if c in segments), None)
                if hit is None:
                    continue
                findings.append(
                    self.make_finding(
                        path,
                        node,
                        f"Classical crypto '{name}' in use. Replace with {REPLACEMENTS.get(hit, 'NIST PQC primitives')}.",
                    )
                )
                break
        return findings
