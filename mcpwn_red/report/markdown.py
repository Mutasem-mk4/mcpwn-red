from __future__ import annotations

from mcpwn_red.attacks.base import ScanReport


def render_markdown(report: ScanReport) -> str:
    lines = [
        "# mcpwn-red Scan Report",
        f"**Date:** {report.timestamp.isoformat()}  **Transport:** {report.transport}",
        "",
        f"**Assessment:** {report.assessment_kind}",
        f"**Policy:** {report.policy.name if report.policy else 'none recorded'}",
        "Probe evidence does not establish exploitation or complete isolation.",
        "Local simulation; no deployment or AI agent assessed."
        if report.assessment_kind == "simulation"
        else "Deployment checks.",
        "",
        "## Summary",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for status in ("PASS", "FAIL", "UNKNOWN", "ERROR"):
        lines.append(f"| {status} | {report.summary.get(status, 0)} |")

    lines.append("")
    if any(result.module == "yaml" for result in report.results):
        lines.append("YAML checks assess tool registration only; no fixture command is executed.")
        lines.append("")
    incomplete = [result for result in report.results if result.status in {"UNKNOWN", "ERROR"}]
    if incomplete:
        lines.extend([
            "## Incomplete Checks",
            "Assessment incomplete (exit 2). Inspect each reason and use probe to verify "
            "available tools before rerunning the relevant module. Missing capabilities "
            "are not evidence that the deployment is safe.",
            "",
        ])
        for result in incomplete:
            lines.extend([
                f"### [{result.status}] {result.id}: {result.name}",
                f"**Reason:** {result.evidence}",
                f"**Recommendation:** {result.recommendation}",
                "",
            ])
    lines.append("## Findings")
    fail_results = [result for result in report.results if result.status == "FAIL"]
    if not fail_results:
        lines.append("No FAIL findings.")
    for result in fail_results:
        lines.extend(
            [
                f"### [FAIL-{result.severity.upper()}] {result.id}: {result.name}",
                f"**Evidence:** {result.evidence}",
                f"**Recommendation:** {result.recommendation}",
                "",
            ]
        )

    lines.extend(
        [
            "## All Results",
            "| ID | Module | Name | Status | Severity | Probe / rule | Evidence kind |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for result in report.results:
        lines.append(
            f"| {result.id} | {result.module} | {result.name} | "
            f"{result.status} | {result.severity} | {result.probe_status or '-'} / "
            f"{result.policy_action or '-'} | {result.evidence_kind or 'unrecorded'} |"
        )
    return "\n".join(lines)
