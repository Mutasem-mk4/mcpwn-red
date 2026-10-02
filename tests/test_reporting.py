from __future__ import annotations

from html.parser import HTMLParser

import pytest

from mcpwn_red.attacks.base import ScanReport, assessment_exit_code
from mcpwn_red.report.html import render_html


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
