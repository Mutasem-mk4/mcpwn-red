from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from mcpwn_red.cli import main
from mcpwn_red.report.json_report import load_json


def test_missing_yaml_executable_returns_error_report(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--module",
            "yaml",
            "--confirm-write",
            "--mcpwn-command",
            str(tmp_path / "missing"),
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 2
    report = load_json(tmp_path / "results.json")
    assert report.summary["ERROR"] == 8
    assert report.summary["PASS"] == 0


def test_yaml_requires_confirmation_before_starting_server(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--module",
            "yaml",
            "--mcpwn-command",
            str(tmp_path / "missing"),
        ],
    )
    assert result.exit_code == 2
    assert "--confirm-write is required" in result.output
    assert "unreachable" not in result.output


def test_output_scan_is_reported_as_simulation(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["scan", "--module", "output", "--output-dir", str(tmp_path)])
    assert result.exit_code == 1, result.output
    report = load_json(tmp_path / "results.json")
    assert report.assessment_kind == "simulation"
    assert report.summary["ERROR"] == 0
