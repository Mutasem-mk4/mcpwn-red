from __future__ import annotations

from mcpwn_red.attacks.base import ScanReport


def render_markdown(report: ScanReport) -> str:
    lines = [
        "# mcpwn-red Scan Report",
        f"**Date:** {report.timestamp.isoformat()}  **Transport:** {report.transport}",
        "",
        "## Summary",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for status in ("PASS", "FAIL", "UNKNOWN", "ERROR"):
        lines.append(f"| {status} | {report.summary.get(status, 0)} |")

    lines.append("")
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
            "| ID | Module | Name | Status | Severity |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for result in report.results:
        lines.append(
            f"| {result.id} | {result.module} | {result.name} | "
            f"{result.status} | {result.severity} |"
        )
    return "\n".join(lines)
