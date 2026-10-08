"""Mapping rules and vulnerability patterns to CWE entries."""

CWE_MAPPINGS = {
    "NTI-IDENT-001": ("CWE-287", "Improper Authentication"),
    "NTI-GOV-001": ("CWE-270", "Incorrect Authorization Context Definition"),
    "NTI-CONS-001": ("CWE-345", "Insufficient Verification of Data Authenticity"),
    "NTI-AUDIT-001": ("CWE-778", "Insufficient Logging"),
    "NTI-PERSIST-001": ("CWE-922", "Insecure Storage of Sensitive Information"),
    "NTI-CAP-DIFF-001": ("CWE-269", "Improper Privilege Management"),
    "NTI-TRUST-BOUND-001": ("CWE-1188", "Insecure Default Initialization"),
    "SEC-PROMPT-001": ("CWE-20", "Improper Input Validation"),
    "SEC-CMD-001": ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command"),
    "SEC-PATH-001": ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory"),
    "SEC-SSRF-001": ("CWE-918", "Server-Side Request Forgery (SSRF)"),
    "SEC-SQL-001": ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command"),
    "SEC-SECRET-001": ("CWE-798", "Use of Hard-coded Credentials"),
    "SEC-DESER-001": ("CWE-502", "Deserialization of Untrusted Data"),
    "SEC-CAP-001": ("CWE-269", "Improper Privilege Management"),
    "SEC-LLM-TRUST-001": ("CWE-346", "Origin Validation Error"),
    "SEC-MCP-001": ("CWE-284", "Improper Access Control"),
    "SEC-A2A-001": ("CWE-306", "Missing Authentication for Critical Function"),
    "SEC-PQC-001": ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
}


def get_cwe_details(rule_id: str) -> dict:
    if rule_id in CWE_MAPPINGS:
        cwe_id, name = CWE_MAPPINGS[rule_id]
        return {"cwe_id": cwe_id, "name": name}
    return {"cwe_id": "CWE-699", "name": "Software Development Vulnerability"}
