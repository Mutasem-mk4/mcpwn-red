from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Literal, cast

import click
from rich.console import Console
from rich.table import Table

from mcpwn_red import __version__
from mcpwn_red.attacks import (
    ContainerBoundaryChecker,
    OutputInjectionSimulator,
    ScopeEscalationTester,
    YamlInjectionTester,
)
from mcpwn_red.attacks.base import ScanReport, summarize_results
from mcpwn_red.mcp_client import MCPClient, MCPClientError
from mcpwn_red.report import load_json, print_report, render_html, render_markdown, save_json

NOTICE = (
    "[mcpwn-red] For authorized use only. "
    "Use only against MCPwn instances you own "
    "or have explicit written permission to test."
)


def _echo_notice() -> None:
    click.echo(NOTICE)


@click.group()
def main() -> None:
    _echo_notice()


@main.command()
@click.option("--transport", type=click.Choice(["stdio", "sse"]), default="stdio")
@click.option("--url", type=str)
@click.option("--timeout", type=int, default=30)
def probe(transport: str, url: str | None, timeout: int) -> None:
    exit_code = asyncio.run(_probe_async(transport=transport, url=url, timeout=timeout))
    raise SystemExit(exit_code)


async def _probe_async(*, transport: str, url: str | None, timeout: int) -> int:
    client = MCPClient(
        transport=cast(Literal["stdio", "sse"], transport),
        url=url,
        timeout=timeout,
    )
    try:
        await client.connect()
        tools = await client.list_tools()
    except MCPClientError as exc:
        click.echo(str(exc), err=True)
        return 1
    finally:
        await client.disconnect()
    click.echo(f"Reachable tools: {len(tools)}")
    return 0


@main.command()
@click.option("--transport", type=click.Choice(["stdio", "sse"]), default="stdio")
@click.option("--url", type=str)
@click.option("--timeout", type=int, default=30)
@click.option(
    "--module",
    "module_name",
    type=click.Choice(["yaml", "output", "container", "scope"]),
)
@click.option("--all", "run_all", is_flag=True)
@click.option("--confirm-write", is_flag=True)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path, file_okay=False, dir_okay=True),
    default=Path("./mcpwn-red-results"),
)
def scan(
    transport: str,
    url: str | None,
    timeout: int,
    module_name: str | None,
    run_all: bool,
    confirm_write: bool,
    output_dir: Path,
) -> None:
    exit_code = asyncio.run(
        _scan_async(
            transport=transport,
            url=url,
            timeout=timeout,
            module_name=module_name,
            run_all=run_all,
            confirm_write=confirm_write,
            output_dir=output_dir,
        )
    )
    raise SystemExit(exit_code)


async def _scan_async(
    *,
    transport: str,
    url: str | None,
    timeout: int,
    module_name: str | None,
    run_all: bool,
    confirm_write: bool,
    output_dir: Path,
) -> int:
    if run_all == (module_name is not None):
        click.echo("Select exactly one of --all or --module.", err=True)
        return 1
    modules = ["yaml", "output", "container", "scope"] if run_all else [str(module_name)]
    results = []
    mcpwn_version: str | None = None
    client = MCPClient(
        transport=cast(Literal["stdio", "sse"], transport),
        url=url,
        timeout=timeout,
    )
    try:
        if any(module in {"yaml", "container", "scope"} for module in modules):
            await client.connect()
            mcpwn_version = client.server_version
        for module in modules:
            if module == "yaml":
                if not confirm_write:
                    click.echo("--confirm-write is required for the yaml module.", err=True)
                    return 1
                yaml_tester = YamlInjectionTester(Path.home() / ".config" / "mcpwn" / "tools")
                results.extend(await yaml_tester.run(client))
            elif module == "output":
                output_tester = OutputInjectionSimulator(timeout=timeout)
                results.extend(await output_tester.run())
            elif module == "container":
                container_tester = ContainerBoundaryChecker()
                results.extend(await container_tester.run(client))
            elif module == "scope":
                scope_tester = ScopeEscalationTester()
                results.extend(await scope_tester.run(client))
    except MCPClientError as exc:
        click.echo(str(exc), err=True)
        return 1
    finally:
        await client.disconnect()

    report = ScanReport(
        version=__version__,
        mcpwn_version=mcpwn_version,
        transport=transport,
        results=results,
        summary=summarize_results(results),
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    save_json(report, output_dir / "results.json")
    print_report(report)
    return report.summary.get("FAIL", 0)


@main.command(name="list")
def list_command() -> None:
    console = Console()
    table = Table(title="mcpwn-red Attack Catalog")
    table.add_column("ID")
    table.add_column("Module")
    table.add_column("Severity")
    table.add_column("Description")
    rows = []
    rows.extend(YamlInjectionTester.catalog())
    rows.extend(OutputInjectionSimulator.catalog())
    rows.extend(ContainerBoundaryChecker.catalog())
    rows.extend(ScopeEscalationTester.catalog())
    for row in rows:
        table.add_row(row["id"], row["module"], row["severity"], row["description"])
    console.print(table)


@main.command()
@click.option(
    "--input",
    "input_path",
    type=click.Path(path_type=Path, exists=True, file_okay=True, dir_okay=False),
    required=True,
)
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["markdown", "html"]),
    default="markdown",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path, file_okay=True, dir_okay=False),
)
def report(input_path: Path, report_format: str, output_path: Path | None) -> None:
    report_obj = load_json(input_path)
    rendered = (
        render_markdown(report_obj)
        if report_format == "markdown"
        else render_html(report_obj)
    )
    if output_path is None:
        click.echo(rendered)
        return
    output_path.write_text(rendered, encoding="utf-8")
