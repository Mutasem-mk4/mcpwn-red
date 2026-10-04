from __future__ import annotations

from html.parser import HTMLParser

import pytest

from mcpwn_red.attacks.base import ScanReport, assessment_exit_code
from mcpwn_red.report.html import render_html
from mcpwn_red.report.markdown import render_markdown
from mcpwn_red.report.terminal import print_report


class ReportText(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text: list[str] = []

    def handle_data(self, data: str) -> None:
        self.text.append(data)


@pytest.mark.parametrize(
    "payload", ["<script>alert(1)</script>", '<img src=x onerror="alert(1)">', "&<b>evidence</b>"]
)
def test_hostile_evidence_renders_as_text(sample_scan_report: ScanReport, payload: str) -> None:
    sample_scan_report.results[0].evidence = payload
    rendered = render_html(sample_scan_report)
    assert payload not in rendered
    parsed = ReportText()
    parsed.feed(rendered)
    assert payload in "".join(parsed.text)


@pytest.mark.parametrize(
    ("summary", "exit_code"),
    [
        ({"PASS": 1}, 0),
        ({"FAIL": 12}, 1),
        ({"ERROR": 1}, 2),
        ({"UNKNOWN": 1}, 2),
        ({"FAIL": 1, "ERROR": 1}, 2),
        ({}, 2),
    ],
)
def test_incomplete_assessment_cannot_exit_successfully(
    summary: dict[str, int], exit_code: int
) -> None:
    assert assessment_exit_code(summary) == exit_code


@pytest.mark.parametrize("status", ["UNKNOWN", "ERROR"])
def test_incomplete_check_reason_and_action_survive_report_export(
    sample_scan_report: ScanReport, status: str, capsys: pytest.CaptureFixture[str]
) -> None:
    result = sample_scan_report.results[0]
    result.status = status
    result.evidence = "nmap unavailable for traversal probe."
    result.recommendation = "Inspect the isolated lab configuration."
    sample_scan_report.summary = {status: 1}
    print_report(sample_scan_report)
    for report_text in (
        capsys.readouterr().out,
        render_markdown(sample_scan_report),
        render_html(sample_scan_report),
    ):
        assert result.evidence in report_text
        assert result.recommendation in report_text
        assert "incomplete" in report_text.lower()


def test_yaml_registration_report_does_not_claim_execution(
    sample_scan_report: ScanReport, capsys: pytest.CaptureFixture[str]
) -> None:
    sample_scan_report.results[0].module = "yaml"
    print_report(sample_scan_report)
    for report_text in (
        capsys.readouterr().out,
        render_markdown(sample_scan_report),
        render_html(sample_scan_report),
    ):
        assert "registration only" in report_text
        assert "no fixture command is executed" in report_text
