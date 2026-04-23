"""Click CLI for mcpwn-red."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import click
from pydantic import ValidationError

from mcpwn_red import __version__
from mcpwn_red.attacks.base import AttackBase, ScanReport
from mcpwn_red.attacks.container_check import ContainerBoundaryChecker
from mcpwn_red.attacks.output_injection import OutputInjectionTester
from mcpwn_red.attacks.scope_escalation import ToolScopeEscalationTester
from mcpwn_red.attacks.yaml_injection import YAMLInjectionTester
from mcpwn_red.mcp_client import MCPClient, MCPClientConfig, MCPClientError
from mcpwn_red.report.html import render_html_report
from mcpwn_red.report.json_report import report_to_json
from mcpwn_red.report.markdown import render_markdown_report
from mcpwn_red.report.terminal import (
    print_attack_catalog,
    print_ethics_reminder,
    print_probe,
    print_scan_report,
)


@dataclass(slots=True)
class AppContext:
    verbose: bool
    timeout: float
    output_dir: Path


def _build_client_config(
    *,
    transport: str,
    timeout: float,
    command: str,
    command_args: tuple[str, ...],
    url: str | None,
) -> MCPClientConfig:
    return MCPClientConfig(
        transport=cast(Literal["stdio", "sse"], transport),
        timeout=timeout,
        command=command,
        command_args=list(command_args),
        url=url,
    )


async def _probe_async(config: MCPClientConfig) -> dict[str, Any]:
    async with MCPClient(config) as client:
        return await client.probe()


async def _scan_async(
    *,
    config: MCPClientConfig,
    modules: list[str],
    confirm_write: bool,
    tools_dir: Path | None,
) -> ScanReport:
    async with MCPClient(config) as probe_client:
        probe = await probe_client.probe()
        mcpwn_version = probe_client.server_version

    runners: list[AttackBase] = []
    for module_name in modules:
        if module_name == "yaml":
            runners.append(YAMLInjectionTester(config, confirm_write=confirm_write, tools_dir=tools_dir))
        elif module_name == "output":
            runners.append(OutputInjectionTester(config))
        elif module_name == "container":
            runners.append(ContainerBoundaryChecker(config))
        elif module_name == "scope":
            runners.append(ToolScopeEscalationTester(config))
        else:
            raise click.ClickException(f"Unknown module {module_name!r}")

    results = []
    for runner in runners:
        results.extend(await runner.run())

    report = ScanReport.from_results(
        version=__version__,
        transport=config.transport,
        results=results,
        mcpwn_version=mcpwn_version or str(probe.get("server_version") or ""),
    )
    return report


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--verbose", is_flag=True, help="Enable verbose console output.")
@click.option("--timeout", default=30.0, show_default=True, type=float, help="Network and tool timeout in seconds.")
@click.option(
    "--output-dir",
    default=Path("./mcpwn-red-results"),
    show_default=True,
    type=click.Path(path_type=Path, file_okay=False, dir_okay=True),
    help="Directory where scan results are saved.",
)
@click.pass_context
def main(ctx: click.Context, verbose: bool, timeout: float, output_dir: Path) -> None:
    """mcpwn-red command line interface."""
    print_ethics_reminder()
    ctx.obj = AppContext(verbose=verbose, timeout=timeout, output_dir=output_dir)


@main.command("probe")
@click.option("--transport", type=click.Choice(["stdio", "sse"]), required=True)
@click.option("--url", type=str, default=None, help="SSE endpoint URL.")
@click.option("--command", type=str, default="mcpwn", show_default=True, help="Command used for stdio transport.")
@click.option(
    "--command-arg",
    "command_args",
    multiple=True,
    help="Repeatable argument passed to the stdio MCPwn command.",
)
@click.pass_obj
def probe_command(app: AppContext, transport: str, url: str | None, command: str, command_args: tuple[str, ...]) -> None:
    """Check whether MCPwn is reachable."""
    config = _build_client_config(
        transport=transport,
        timeout=app.timeout,
        command=command,
        command_args=command_args,
        url=url,
    )
    try:
        probe = asyncio.run(_probe_async(config))
    except MCPClientError as exc:
        raise click.ClickException(str(exc)) from exc
    print_probe(probe)


@main.command("list")
def list_command() -> None:
    """List all implemented attack checks."""
    items = []
    items.extend(YAMLInjectionTester.describe())
    items.extend(OutputInjectionTester.describe())
    items.extend(ContainerBoundaryChecker.describe())
    items.extend(ToolScopeEscalationTester.describe())
    print_attack_catalog(items)


@main.command("scan")
@click.option("--transport", type=click.Choice(["stdio", "sse"]), required=True)
@click.option("--url", type=str, default=None, help="SSE endpoint URL.")
@click.option("--command", type=str, default="mcpwn", show_default=True, help="Command used for stdio transport.")
@click.option(
    "--command-arg",
    "command_args",
    multiple=True,
    help="Repeatable argument passed to the stdio MCPwn command.",
)
@click.option("--all", "scan_all", is_flag=True, help="Run all modules.")
@click.option("--module", "module_name", type=click.Choice(["yaml", "output", "container", "scope"]))
@click.option("--confirm-write", is_flag=True, help="Required before the YAML module writes into the MCPwn tools directory.")
@click.option(
    "--tools-dir",
    type=click.Path(path_type=Path, file_okay=False, dir_okay=True),
    default=None,
    help="Override the MCPwn YAML tool directory.",
)
@click.pass_obj
def scan_command(
    app: AppContext,
    transport: str,
    url: str | None,
    command: str,
    command_args: tuple[str, ...],
    scan_all: bool,
    module_name: str | None,
    confirm_write: bool,
    tools_dir: Path | None,
) -> None:
    """Run attack modules against an MCPwn instance."""
    if scan_all == (module_name is not None):
        raise click.ClickException("Select either --all or exactly one --module.")

    modules = ["yaml", "output", "container", "scope"] if scan_all else [str(module_name)]
    config = _build_client_config(
        transport=transport,
        timeout=app.timeout,
        command=command,
        command_args=command_args,
        url=url,
    )
    try:
        report = asyncio.run(
            _scan_async(
                config=config,
                modules=modules,
                confirm_write=confirm_write,
                tools_dir=tools_dir,
            )
        )
    except (MCPClientError, PermissionError) as exc:
        raise click.ClickException(str(exc)) from exc

    app.output_dir.mkdir(parents=True, exist_ok=True)
    output_path = app.output_dir / "results.json"
    output_path.write_text(report_to_json(report), encoding="utf-8")
    print_scan_report(report)
    click.echo(f"Saved JSON report to {output_path}")


@main.command("report")
@click.option("--input", "input_path", type=click.Path(path_type=Path, exists=True, dir_okay=False), required=True)
@click.option("--format", "report_format", type=click.Choice(["json", "markdown", "html"]), required=True)
def report_command(input_path: Path, report_format: str) -> None:
    """Render a saved report as JSON, Markdown, or HTML."""
    try:
        report = ScanReport.model_validate_json(input_path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise click.ClickException(f"Unable to read report input {input_path}: {exc}") from exc
    if report_format == "json":
        click.echo(report_to_json(report))
        return
    if report_format == "markdown":
        click.echo(render_markdown_report(report))
        return
    click.echo(render_html_report(report))
