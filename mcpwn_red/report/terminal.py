from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcpwn_red import __version__
from mcpwn_red.attacks.base import ScanReport


def print_report(report: ScanReport) -> None:
    console = Console()
    console.print(Panel(f"mcpwn-red v{__version__} | {report.assessment_kind}", style="bold cyan"))
    if report.assessment_kind == "deployment":
        console.print(Text(f"Policy: {report.policy.name if report.policy else 'none recorded'}"))
        console.print(
            "Results concern declared policy and probe evidence; they do not prove exploitation."
        )

    table = Table(title="Attack Results")
    table.add_column("ID")
    table.add_column("Module")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Probe / rule")
    status_styles = {
        "PASS": "green",
        "FAIL": "red",
        "UNKNOWN": "yellow",
        "ERROR": "orange3",
    }
    for result in report.results:
        table.add_row(
            result.id,
            result.module,
            result.name,
            f"[{status_styles[result.status]}]{result.status}[/{status_styles[result.status]}]",
            result.severity,
            f"{result.probe_status or '-'} / {result.policy_action or '-'}",
        )
    console.print(table)

    summary_lines = [
        f"PASS: {report.summary.get('PASS', 0)}",
        f"FAIL: {report.summary.get('FAIL', 0)}",
        f"UNKNOWN: {report.summary.get('UNKNOWN', 0)}",
        f"ERROR: {report.summary.get('ERROR', 0)}",
    ]
    console.print(Panel("\n".join(summary_lines), title="Summary"))

    if any(result.module == "yaml" for result in report.results):
        console.print("YAML checks assess tool registration only; no fixture command is executed.")
    for result in report.results:
        if result.status in {"UNKNOWN", "ERROR"}:
            console.print(
                Panel(
                    Text(f"Reason: {result.evidence}\nRecommendation: {result.recommendation}"),
                    title=Text(f"{result.id}: {result.status} — check incomplete"),
                )
            )
    if report.summary.get("UNKNOWN", 0) or report.summary.get("ERROR", 0):
        console.print(
            "Assessment incomplete (exit 2). Inspect the reasons and verify the server's "
            "available tools with probe before rerunning the relevant module. "
            "A missing capability is not proof that the deployment is safe."
        )

    fail_count = report.summary.get("FAIL", 0)
    if fail_count and report.assessment_kind == "deployment":
        console.print(
            Panel(
                f"{fail_count} checks disagree with the declared policy. Review the evidence.",
                title="Warning",
                style="bold red",
            )
        )
