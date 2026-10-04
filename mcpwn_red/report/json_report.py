from __future__ import annotations

from pathlib import Path

from mcpwn_red.attacks.base import ScanReport


def save_json(report: ScanReport, path: Path) -> None:
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def load_json(path: Path) -> ScanReport:
    return ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
