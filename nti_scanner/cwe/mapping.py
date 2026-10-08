"""CWE metadata lookup."""
CWE_NAMES = {"CWE-22": "Path Traversal", "CWE-78": "OS Command Injection", "CWE-89": "SQL Injection",
             "CWE-269": "Privilege Management", "CWE-287": "Authentication", "CWE-353": "Missing Integrity",
             "CWE-502": "Unsafe Deserialization", "CWE-778": "Insufficient Logging", "CWE-798": "Hardcoded Credentials",
             "CWE-862": "Missing Authorization", "CWE-918": "SSRF", "CWE-1336": "Template Injection",
             "CWE-1426": "AI Output Validation"}


def cwe_url(cwe: str) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"
