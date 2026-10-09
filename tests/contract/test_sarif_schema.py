"""SARIF output must be valid 2.1.0."""
import json
from nti_scanner.report.sarif import render_sarif
from nti_scanner.scanner import ScanResult


def test_sarif_valid_json(tmp_path):
    result = ScanResult(path=str(tmp_path))
    out = render_sarif(result)
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert "runs" in data


def test_sarif_has_tool_metadata(tmp_path):
    result = ScanResult(path=str(tmp_path))
    data = json.loads(render_sarif(result))
    assert data["runs"][0]["tool"]["driver"]["name"] == "nti-scanner"


def test_sarif_rules_declared(tmp_path):
    result = ScanResult(path=str(tmp_path))
    data = json.loads(render_sarif(result))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) >= 19
