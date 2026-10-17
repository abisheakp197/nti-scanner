"""JSON report."""
import json

from nti_scanner.scanner import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
