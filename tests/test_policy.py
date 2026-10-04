from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from mcpwn_red.attacks.base import AttackResult, ScanReport, assessment_exit_code, summarize_results
from mcpwn_red.cli import main
from mcpwn_red.policy import AssessmentPolicy, PolicyRule, evaluate_policy
from mcpwn_red.report import load_json, render_html, render_markdown, save_json


@pytest.mark.parametrize(
    ("probe_status", "action", "expected"),
    [
        ("FAIL", None, "UNKNOWN"),
        ("PASS", None, "UNKNOWN"),
        ("FAIL", "allow", "PASS"),
        ("PASS", "allow", "UNKNOWN"),
        ("FAIL", "deny", "FAIL"),
        ("PASS", "deny", "PASS"),
        ("UNKNOWN", "allow", "UNKNOWN"),
        ("ERROR", "allow", "ERROR"),
        ("UNKNOWN", "deny", "UNKNOWN"),
        ("ERROR", "deny", "ERROR"),
    ],
)
def test_policy_cannot_hide_incomplete_checks(
    probe_status: str, action: str | None, expected: str
) -> None:
    probe = AttackResult(
        id="YAML-01",
        name="shell",
        module="yaml",
        status=probe_status,
        severity="critical",
        evidence="Registration observation",
        duration_ms=1,
        recommendation="Review",
    )
    policy = (
        AssessmentPolicy(name="Operator policy", checks={"YAML-01": PolicyRule(action=action)})
        if action
        else None
    )
    judged = evaluate_policy(probe, policy)
    assert judged.status == expected
    assert judged.probe_status == probe_status and judged.evidence == probe.evidence
    assert judged.evidence_kind == "registration"
    assert probe.status == probe_status
    if expected in {"UNKNOWN", "ERROR"}:
        assert assessment_exit_code(summarize_results([judged])) == 2


@pytest.mark.parametrize(
    "policy_text",
    [
        "{",
        '{"name":"typo","checks":{"YAML-99":{"action":"deny"}}}',
        '{"name":"bad","checks":{"YAML-01":{"action":"ignore"}}}',
        '{"name":"empty","checks":{}}',
        '{"name":"bad","checks":{"YAML-01":{"action":"deny","unexpected":1}}}',
    ],
)
def test_invalid_policy_fails_before_starting_scan(tmp_path: Path, policy_text: str) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(policy_text, encoding="utf-8")
    destination = tmp_path / "report"
    response = CliRunner().invoke(
        main,
        [
            "scan",
            "--module",
            "yaml",
            "--confirm-write",
            "--mcpwn-command",
            str(tmp_path / "missing"),
            "--policy",
            str(policy_file),
            "--output-dir",
            str(destination),
        ],
    )
    assert response.exit_code == 2
    assert "--policy" in response.output and "Traceback" not in response.output
    assert not destination.exists()


def test_policy_and_observation_survive_report_roundtrip(tmp_path: Path) -> None:
    policy = AssessmentPolicy(
        name="Allow <shell> registration", checks={"YAML-01": PolicyRule(action="allow")}
    )
    probe = AttackResult(
        id="YAML-01",
        name="shell",
        module="yaml",
        status="FAIL",
        severity="critical",
        evidence="Registered",
        duration_ms=1,
        recommendation="Review",
    )
    judged = evaluate_policy(probe, policy)
    report = ScanReport(
        version="0.2.0",
        mcpwn_version=None,
        transport="stdio",
        policy=policy,
        results=[judged],
        summary=summarize_results([judged]),
    )
    destination = tmp_path / "results.json"
    save_json(report, destination)
    restored = load_json(destination)
    assert restored.policy == policy
    assert restored.results[0].probe_status == "FAIL" and restored.results[0].status == "PASS"
    assert "FAIL / allow" in render_markdown(restored)
    rendered = render_html(restored)
    assert "FAIL / allow" in rendered and "registration" in rendered
    assert "Allow &lt;shell&gt; registration" in rendered
