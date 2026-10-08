"""SARIF 2.1.0 reporter for GitHub Security integration."""
import json
from nti_scanner.rules.registry import RULES


SEVERITY_TO_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def render_sarif(result) -> str:
    rules_meta = []
    for r in RULES:
        rules_meta.append({"id": r.meta.id, "name": r.meta.id,
                           "shortDescription": {"text": r.meta.description},
                           "helpUri": f"https://cwe.mitre.org/data/definitions/{r.meta.cwe.replace('CWE-','')}.html" if r.meta.cwe else "",
                           "properties": {"category": r.meta.category, "confidence": r.meta.confidence}})
    sarif_results = []
    for f in result.findings:
        sarif_results.append({"ruleId": f.rule_id, "level": SEVERITY_TO_LEVEL.get(f.severity, "warning"),
                              "message": {"text": f.message},
                              "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                                                    "region": {"startLine": max(1, f.line), "startColumn": max(1, f.column)}}}],
                              "properties": {"cwe": f.cwe, "confidence": f.confidence}})
    sarif = {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
             "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "nti-scanner",
                                            "informationUri": "https://github.com/abisheakp197/nti-scanner",
                                            "version": "0.1.0", "rules": rules_meta}},
                       "results": sarif_results}]}
    return json.dumps(sarif, indent=2)
