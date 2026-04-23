"""JSON report rendering."""

from __future__ import annotations

import json

from mcpwn_red.attacks.base import ScanReport


def report_to_json(report: ScanReport, *, pretty: bool = True) -> str:
    payload = report.model_dump(mode="json")
    if pretty:
        return json.dumps(payload, indent=2, sort_keys=True)
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)

