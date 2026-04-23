from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcpwn_red.attacks.base import ScanReport


def print_report(report: ScanReport) -> None:
    console = Console()
    console.print(Panel("mcpwn-red v0.1.0 | Parrot OS", style="bold cyan"))

    table = Table(title="Attack Results")
    table.add_column("ID")
    table.add_column("Module")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Severity")
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
        )
    console.print(table)

    summary_lines = [
        f"PASS: {report.summary.get('PASS', 0)}",
        f"FAIL: {report.summary.get('FAIL', 0)}",
        f"UNKNOWN: {report.summary.get('UNKNOWN', 0)}",
        f"ERROR: {report.summary.get('ERROR', 0)}",
    ]
    console.print(Panel("\n".join(summary_lines), title="Summary"))

    fail_count = report.summary.get("FAIL", 0)
    if fail_count:
        console.print(
            Panel(
                f"{fail_count} failing security checks require remediation.",
                title="Warning",
                style="bold red",
            )
        )
