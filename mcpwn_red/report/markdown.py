"""Markdown report renderer."""

from __future__ import annotations

from mcpwn_red.attacks.base import ScanReport


def render_markdown_report(report: ScanReport) -> str:
    lines = [
        f"# {report.tool} Report",
        "",
        f"- Version: `{report.version}`",
        f"- Timestamp: `{report.timestamp.isoformat()}`",
        f"- MCPwn version: `{report.mcpwn_version or 'unknown'}`",
        f"- Transport: `{report.transport}`",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for key in ("PASS", "FAIL", "UNKNOWN", "ERROR"):
        lines.append(f"| {key} | {report.summary.get(key, 0)} |")
    lines.extend(["", "## Results", "", "| ID | Module | Status | Severity | Name | Evidence | Recommendation |", "| --- | --- | --- | --- | --- | --- | --- |"])
    for result in report.results:
        evidence = result.evidence.replace("\n", "<br>")
        recommendation = result.recommendation.replace("\n", "<br>")
        lines.append(
            f"| {result.id} | {result.module} | {result.status} | {result.severity} | {result.name} | {evidence} | {recommendation} |"
        )
    return "\n".join(lines)

