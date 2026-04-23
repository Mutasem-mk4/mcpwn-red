"""Terminal rendering helpers."""

from __future__ import annotations

from collections.abc import Iterable

from rich.console import Console
from rich.table import Table

from mcpwn_red.attacks.base import ScanReport

console = Console()


def print_ethics_reminder() -> None:
    console.print(
        "[bold yellow]Authorized use only:[/bold yellow] run mcpwn-red only against MCPwn instances and environments you are explicitly permitted to assess."
    )


def print_probe(probe: dict[str, object]) -> None:
    table = Table(title="MCPwn Probe")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    for key, value in probe.items():
        table.add_row(key, str(value))
    console.print(table)


def print_attack_catalog(items: Iterable[dict[str, str]]) -> None:
    table = Table(title="Available Tests")
    table.add_column("ID", style="cyan")
    table.add_column("Module", style="magenta")
    table.add_column("Name", style="white")
    table.add_column("Description", style="green")
    for item in items:
        table.add_row(item["id"], item["module"], item["name"], item["description"])
    console.print(table)


def print_scan_report(report: ScanReport) -> None:
    summary = Table(title=f"mcpwn-red {report.version} Summary")
    summary.add_column("Status", style="cyan")
    summary.add_column("Count", justify="right")
    for key in ("PASS", "FAIL", "UNKNOWN", "ERROR"):
        summary.add_row(key, str(report.summary.get(key, 0)))
    console.print(summary)

    results_table = Table(title="Attack Results", show_lines=True)
    results_table.add_column("ID", style="cyan")
    results_table.add_column("Module", style="magenta")
    results_table.add_column("Status")
    results_table.add_column("Severity")
    results_table.add_column("Name", style="white")
    results_table.add_column("Evidence", style="green")
    for result in report.results:
        status_style = {
            "PASS": "bold green",
            "FAIL": "bold red",
            "UNKNOWN": "bold yellow",
            "ERROR": "bold bright_red",
        }[result.status]
        results_table.add_row(
            result.id,
            result.module,
            f"[{status_style}]{result.status}[/{status_style}]",
            result.severity,
            result.name,
            result.evidence,
        )
    console.print(results_table)
