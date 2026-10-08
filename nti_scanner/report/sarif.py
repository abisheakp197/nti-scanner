"""SARIF v2.1.0 generator for GitHub Security tab integration."""

import json


def render_sarif(result) -> str:
    rules_dict = {}
    sarif_results = []

    severity_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    for f in result.findings:
        if f.rule_id not in rules_dict:
            rules_dict[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.category},
                "fullDescription": {"text": f.message},
                "help": {"text": f.remediation or f.message},
                "properties": {
                    "category": f.category,
                    "cwe": f.cwe or [],
                },
            }

        sarif_results.append({
            "ruleId": f.rule_id,
            "level": severity_map.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {
                            "startLine": f.line or 1,
                            "startColumn": f.column or 1,
                        },
                    }
                }
            ],
        })

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "nti-scanner",
                        "version": "0.1.0",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)
