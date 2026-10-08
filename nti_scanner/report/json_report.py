"""JSON report renderer."""

import json


def render_json(result) -> str:
    return json.dumps(result.to_dict(), indent=2)
