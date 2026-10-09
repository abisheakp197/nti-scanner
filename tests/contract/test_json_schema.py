"""JSON output contract."""
import json
from nti_scanner.scanner import scan_directory, Finding, ScanResult
from pathlib import Path


def test_scan_result_to_dict_shape(tmp_path):
    result = ScanResult(path=str(tmp_path))
    d = result.to_dict()
    assert "version" in d
    assert "path" in d
    assert "frameworks" in d
    assert "nti1_score" in d
    assert "findings" in d
    assert isinstance(d["findings"], list)


def test_scan_result_json_serializable(tmp_path):
    result = ScanResult(path=str(tmp_path))
    payload = json.dumps(result.to_dict())
    assert isinstance(payload, str)


def test_finding_to_dict():
    f = Finding(rule_id="X-1", category="Test", severity="high",
                confidence="high", message="m", file="f.py", line=1, column=0)
    d = f.__dict__
    assert d["rule_id"] == "X-1"
    assert d["severity"] == "high"
