"""SARIF output must be valid 2.1.0 schema compliant."""
import json
from pathlib import Path

from jsonschema import validate

from nti_scanner.report.sarif import render_sarif
from nti_scanner.rules.base import Finding
from nti_scanner.scanner import ScanResult

SARIF_MINIMAL_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["$schema", "version", "runs"],
    "properties": {
        "version": {"type": "string", "const": "2.1.0"},
        "$schema": {"type": "string"},
        "runs": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["tool", "results"],
                "properties": {
                    "tool": {
                        "type": "object",
                        "required": ["driver"],
                        "properties": {
                            "driver": {
                                "type": "object",
                                "required": ["name", "version", "rules"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "version": {"type": "string"},
                                    "rules": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "required": ["id", "shortDescription"],
                                            "properties": {
                                                "id": {"type": "string"},
                                                "shortDescription": {
                                                    "type": "object",
                                                    "required": ["text"],
                                                    "properties": {"text": {"type": "string"}},
                                                },
                                            },
                                        },
                                    },
                                },
                            }
                        },
                    },
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["ruleId", "level", "message", "locations"],
                            "properties": {
                                "ruleId": {"type": "string"},
                                "level": {"type": "string", "enum": ["error", "warning", "note", "none"]},
                                "message": {
                                    "type": "object",
                                    "required": ["text"],
                                    "properties": {"text": {"type": "string"}},
                                },
                                "locations": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["physicalLocation"],
                                        "properties": {
                                            "physicalLocation": {
                                                "type": "object",
                                                "required": ["artifactLocation", "region"],
                                                "properties": {
                                                    "artifactLocation": {
                                                        "type": "object",
                                                        "required": ["uri"],
                                                        "properties": {"uri": {"type": "string"}},
                                                    },
                                                    "region": {
                                                        "type": "object",
                                                        "required": ["startLine", "startColumn"],
                                                        "properties": {
                                                            "startLine": {"type": "integer", "minimum": 1},
                                                            "startColumn": {"type": "integer", "minimum": 1},
                                                        },
                                                    },
                                                },
                                            }
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
}


def test_sarif_valid_json(tmp_path: Path) -> None:
    result = ScanResult(path=str(tmp_path))
    out = render_sarif(result)
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    validate(instance=data, schema=SARIF_MINIMAL_SCHEMA)


def test_sarif_has_tool_metadata(tmp_path: Path) -> None:
    result = ScanResult(path=str(tmp_path))
    data = json.loads(render_sarif(result))
    assert data["runs"][0]["tool"]["driver"]["name"] == "nti-scanner"
    validate(instance=data, schema=SARIF_MINIMAL_SCHEMA)


def test_sarif_rules_declared(tmp_path: Path) -> None:
    result = ScanResult(path=str(tmp_path))
    data = json.loads(render_sarif(result))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) >= 19
    validate(instance=data, schema=SARIF_MINIMAL_SCHEMA)


def test_sarif_with_findings_validates_schema(tmp_path: Path) -> None:
    result = ScanResult(path=str(tmp_path))
    result.findings.append(
        Finding(
            rule_id="SEC-CMD-001",
            category="Security",
            severity="critical",
            confidence="high",
            message="Direct shell execution",
            file=str(tmp_path / "app.py"),
            line=10,
            column=5,
            cwe="CWE-78",
            remediation="Avoid shell=True",
        )
    )
    data = json.loads(render_sarif(result))
    validate(instance=data, schema=SARIF_MINIMAL_SCHEMA)
    loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == (tmp_path / "app.py").as_posix()
    assert "\\" not in loc["artifactLocation"]["uri"]
