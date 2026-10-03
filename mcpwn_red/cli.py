from __future__ import annotations

import asyncio
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as metadata_version
from pathlib import Path
from typing import Literal, cast

import click
from pydantic import ValidationError
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcpwn_red import __version__
from mcpwn_red.attacks import (
    ContainerBoundaryChecker,
    OutputInjectionSimulator,
    ScopeEscalationTester,
    YamlInjectionTester,
)
from mcpwn_red.attacks.base import ScanReport, assessment_exit_code, summarize_results
from mcpwn_red.mcp_client import MCPClient, MCPClientError
from mcpwn_red.policy import AssessmentPolicy, evaluate_policy
from mcpwn_red.report import load_json, print_report, render_html, render_markdown, save_json

BANNER = r"""
  __  __  _____ _____               _   _      _____  ______ _____  
 |  \/  |/ ____|  __ \             | \ | |    |  __ \|  ____|  __ \ 
 | \  / | |    | |__) |_      ___  |  \| |____| |__) | |__  | |  | |
 | |\/| | |    |  ___/\ \ /\ / / _ \ | . ` |____|  _  /|  __| | |  | |
 | |  | | |____| |     \ V  V /  __/ | |\  |    | | \ \| |____| |__| |
 |_|  |_|\_____|_|      \_/\_/ \___| |_| \_|    |_|  \_\______|_____/ 
                                                                    
"""

NOTICE = (
    "FOR AUTHORIZED USE ONLY. "
    "Use only against MCPwn instances you own "
    "or have explicit written permission to test."
)


def _package_version() -> str:
    try:
        return metadata_version("mcpwn-red")
    except PackageNotFoundError:
        return __version__


def _echo_banner() -> None:
    console = Console()
    console.print(Align.center(f"[bold red]{BANNER}[/bold red]"))
    version_text = f"v{_package_version()} | Adversarial Safety Harness for MCPwn"
    console.print(Align.center(f"[bold white]{version_text}[/bold white]\n"))


def _echo_notice() -> None:
    console = Console(stderr=True)
    panel = Panel(
        NOTICE,
        title="[bold red]ETHICAL USE ENFORCEMENT[/bold red]",
        border_style="red",
    )
    console.print(panel)


@click.group()
@click.version_option(version=_package_version(), prog_name="mcpwn-red")
def main() -> None:
    _echo_banner()
    _echo_notice()


@main.command()
@click.option("--transport", type=click.Choice(["stdio", "sse"]), default="stdio")
@click.option("--url", type=str)
@click.option("--timeout", type=click.IntRange(min=1), default=30)
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
@click.option("--timeout", type=click.IntRange(min=1), default=30)
@click.option("--mcpwn-command", default="mcpwn", help="MCPwn executable for stdio/YAML tests.")
@click.option(
    "--module",
    "module_name",
    type=click.Choice(["yaml", "output", "container", "scope"]),
)
@click.option("--all", "run_all", is_flag=True)
@click.option("--confirm-write", is_flag=True)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="JSON policy declaring allow/deny rules by check ID.",
)
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
    mcpwn_command: str,
    policy_path: Path | None,
) -> None:
    policy = _load_policy(policy_path)
    exit_code = asyncio.run(
        _scan_async(
            transport=transport,
            url=url,
            timeout=timeout,
            module_name=module_name,
            run_all=run_all,
            confirm_write=confirm_write,
            output_dir=output_dir,
            mcpwn_command=mcpwn_command,
            policy=policy,
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
    mcpwn_command: str = "mcpwn",
    policy: AssessmentPolicy | None = None,
) -> int:
    if run_all == (module_name is not None):
        click.echo("Select exactly one of --all or --module.", err=True)
        return 2
    if module_name == "output" and policy is not None:
        click.echo(
            "--policy applies to deployment checks, not the local output simulation.", err=True
        )
        return 2
    modules = ["yaml", "container", "scope"] if run_all else [str(module_name)]
    if "yaml" in modules and not confirm_write:
        click.echo("--confirm-write is required for the yaml module.", err=True)
        return 2
    results = []
    mcpwn_version: str | None = None
    client = MCPClient(
        transport=cast(Literal["stdio", "sse"], transport),
        url=url,
        timeout=timeout,
        command=mcpwn_command,
    )
    try:
        if any(module in {"container", "scope"} for module in modules):
            await client.connect()
            mcpwn_version = client.server_version
        for module in modules:
            if module == "yaml":
                yaml_tester = YamlInjectionTester(command=mcpwn_command, timeout=timeout)
                results.extend(await yaml_tester.run())
            elif module == "output":
                click.echo(
                    "Output module runs a local payload simulation; it does not assess the target.",
                    err=True,
                )
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
        return 2
    finally:
        await client.disconnect()

    if module_name != "output":
        results = [evaluate_policy(probe, policy) for probe in results]
    report = ScanReport(
        version=__version__,
        mcpwn_version=mcpwn_version,
        transport=transport,
        assessment_kind="simulation" if module_name == "output" else "deployment",
        policy=policy,
        results=results,
        summary=summarize_results(results),
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    save_json(report, output_dir / "results.json")
    print_report(report)
    return assessment_exit_code(report.summary)


def _load_policy(path: Path | None) -> AssessmentPolicy | None:
    if path is None:
        return None
    try:
        policy = AssessmentPolicy.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValidationError) as exc:
        raise click.BadParameter(str(exc), param_hint="--policy") from exc
    known = {
        row["id"]
        for tester in (YamlInjectionTester, ContainerBoundaryChecker, ScopeEscalationTester)
        for row in tester.catalog()
    }
    unknown = policy.checks.keys() - known
    if unknown:
        raise click.BadParameter(
            f"Unknown check IDs: {', '.join(sorted(unknown))}", param_hint="--policy"
        )
    return policy


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
        render_markdown(report_obj) if report_format == "markdown" else render_html(report_obj)
    )
    if output_path is None:
        click.echo(rendered)
        return
    output_path.write_text(rendered, encoding="utf-8")
