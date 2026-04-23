"""Container-boundary checks executed through MCPwn tools."""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter

from mcpwn_red.attacks.base import (
    AttackBase,
    AttackStatus,
    AttackResult,
    Severity,
    ToolReference,
    build_arguments,
    extract_text_content,
    find_tool,
)
from mcpwn_red.mcp_client import MCPClient, MCPClientConfig, MCPClientError


@dataclass(frozen=True, slots=True)
class BoundaryCheck:
    attack_id: str
    name: str
    severity: Severity
    preferred_tools: tuple[str, ...]
    logical_arguments: dict[str, str]
    kind: str
    description: str
    recommendation: str


BOUNDARY_CHECKS: tuple[BoundaryCheck, ...] = (
    BoundaryCheck(
        attack_id="CNT-01",
        name="Nmap Path Traversal Argument",
        severity="medium",
        preferred_tools=("nmap",),
        logical_arguments={"target": "../../etc/passwd", "ports": "80"},
        kind="literal_target",
        description="Checks whether a traversal string is passed literally to nmap or interpreted as host file access.",
        recommendation="Validate target arguments against host/IP syntax before they reach the containerized tool.",
    ),
    BoundaryCheck(
        attack_id="CNT-02",
        name="Gobuster Host Shadow Probe",
        severity="critical",
        preferred_tools=("gobuster",),
        logical_arguments={"url": "http://127.0.0.1", "wordlist": "/host/etc/shadow", "threads": "1"},
        kind="mounted_path_absent",
        description="Verifies that obvious host mount paths are not readable inside the container.",
        recommendation="Remove broad host bind mounts and confine file inputs to a dedicated in-container workspace.",
    ),
    BoundaryCheck(
        attack_id="CNT-03",
        name="DOCKER_HOST Environment Expansion",
        severity="high",
        preferred_tools=("nmap",),
        logical_arguments={"target": "${DOCKER_HOST}", "ports": "80"},
        kind="env_literal",
        description="Checks whether MCPwn shells out in a way that expands DOCKER_HOST.",
        recommendation="Invoke tools via exec-style APIs and pass environment variables through an explicit allowlist.",
    ),
    BoundaryCheck(
        attack_id="CNT-04",
        name="AWS Secret Environment Expansion",
        severity="critical",
        preferred_tools=("nmap",),
        logical_arguments={"target": "${AWS_SECRET_ACCESS_KEY}", "ports": "80"},
        kind="env_literal",
        description="Checks whether high-value environment variables are expanded inside tool arguments.",
        recommendation="Clear sensitive environment variables before container start and avoid shell interpolation entirely.",
    ),
    BoundaryCheck(
        attack_id="CNT-05",
        name="HOME Environment File Probe",
        severity="high",
        preferred_tools=("gobuster",),
        logical_arguments={"url": "http://127.0.0.1", "wordlist": "${HOME}/.bashrc", "threads": "1"},
        kind="env_path_literal",
        description="Checks whether a wordlist path expands against the container user home directory.",
        recommendation="Disable shell expansion in file-path arguments and pin tool inputs to controlled directories only.",
    ),
    BoundaryCheck(
        attack_id="CNT-06",
        name="Docker Socket Exposure",
        severity="critical",
        preferred_tools=("gobuster",),
        logical_arguments={"url": "http://127.0.0.1", "wordlist": "/var/run/docker.sock", "threads": "1"},
        kind="socket_absent",
        description="Ensures /var/run/docker.sock is not mounted into the tool container.",
        recommendation="Never mount the Docker socket into MCPwn containers; use rootless isolated runtimes instead.",
    ),
    BoundaryCheck(
        attack_id="CNT-07",
        name="Bridge Gateway Reachability",
        severity="high",
        preferred_tools=("nmap",),
        logical_arguments={"target": "172.17.0.1", "ports": "22"},
        kind="bridge_blocked",
        description="Checks whether a tool can pivot toward the default Docker bridge gateway.",
        recommendation="Apply egress filtering that blocks container access to local bridge and host-management networks.",
    ),
    BoundaryCheck(
        attack_id="CNT-08",
        name="Proc Root Host Mount Probe",
        severity="critical",
        preferred_tools=("gobuster",),
        logical_arguments={"url": "http://127.0.0.1", "wordlist": "/proc/1/root/etc/passwd", "threads": "1"},
        kind="mounted_path_absent",
        description="Checks whether procfs exposes host-root paths to file-consuming tools.",
        recommendation="Harden procfs exposure and run containers with PID namespaces that do not leak host roots.",
    ),
    BoundaryCheck(
        attack_id="CNT-09",
        name="Legacy Host Mount Probe",
        severity="high",
        preferred_tools=("gobuster",),
        logical_arguments={"url": "http://127.0.0.1", "wordlist": "/host/etc/hosts", "threads": "1"},
        kind="mounted_path_absent",
        description="Checks for traditional /host-style bind mounts inside the container.",
        recommendation="Eliminate convenience mounts such as /host and map only the minimal authorized workspace path.",
    ),
    BoundaryCheck(
        attack_id="CNT-10",
        name="Mnt Host Mount Probe",
        severity="high",
        preferred_tools=("gobuster",),
        logical_arguments={"url": "http://127.0.0.1", "wordlist": "/mnt/host/etc/hosts", "threads": "1"},
        kind="mounted_path_absent",
        description="Checks for host exposure through /mnt/host-style volume mappings.",
        recommendation="Audit container volume mappings and remove host-root mounts beyond the intended workspace.",
    ),
)

_NOT_FOUND_MARKERS = ("no such file", "not found", "does not exist", "cannot find")
_EXECUTION_MARKERS = ("starting nmap", "nmap scan report", "gobuster", "progress", "status")


class ContainerBoundaryChecker(AttackBase):
    module = "container"

    def __init__(self, client_config: MCPClientConfig) -> None:
        self.client_config = client_config

    @classmethod
    def describe(cls) -> list[dict[str, str]]:
        return [
            {
                "id": check.attack_id,
                "module": cls.module,
                "name": check.name,
                "description": check.description,
            }
            for check in BOUNDARY_CHECKS
        ]

    async def run(self) -> list[AttackResult]:
        async with MCPClient(self.client_config) as client:
            tools = await client.list_tool_refs()
            results: list[AttackResult] = []
            for check in BOUNDARY_CHECKS:
                results.append(await self._run_check(client, tools, check))
            return results

    async def _run_check(
        self,
        client: MCPClient,
        tools: list[ToolReference],
        check: BoundaryCheck,
    ) -> AttackResult:
        started_at = perf_counter()
        tool = find_tool(tools, check.preferred_tools)
        if tool is None:
            return self.build_result(
                attack_id=check.attack_id,
                name=check.name,
                status="UNKNOWN",
                severity=check.severity,
                evidence=f"Required tool family {check.preferred_tools!r} is not exposed by MCPwn.",
                started_at=started_at,
                recommendation=check.recommendation,
            )

        arguments = build_arguments(tool, check.logical_arguments)
        try:
            result = await client.call_tool(tool.name, arguments)
        except MCPClientError as exc:
            return self.build_result(
                attack_id=check.attack_id,
                name=check.name,
                status="ERROR",
                severity=check.severity,
                evidence=f"Tool call {tool.name!r} with {arguments!r} failed: {exc}",
                started_at=started_at,
                recommendation=check.recommendation,
            )

        response_text = extract_text_content(result)
        status = self._classify(check, response_text, is_error=result.isError)
        evidence = f"Tool={tool.name!r} arguments={arguments!r} is_error={result.isError} response={response_text!r}"
        return self.build_result(
            attack_id=check.attack_id,
            name=check.name,
            status=status,
            severity=check.severity,
            evidence=evidence,
            started_at=started_at,
            recommendation=check.recommendation,
        )

    def _classify(
        self,
        check: BoundaryCheck,
        response_text: str,
        *,
        is_error: bool,
    ) -> AttackStatus:
        lower = response_text.lower()
        probe_value = (
            check.logical_arguments.get("wordlist")
            or check.logical_arguments.get("target")
            or check.logical_arguments.get("command")
            or ""
        )

        if check.kind == "literal_target":
            if probe_value in response_text or "resolve" in lower or "invalid" in lower or is_error:
                return "PASS"
            if any(marker in lower for marker in _EXECUTION_MARKERS):
                return "FAIL"
            return "UNKNOWN"

        if check.kind == "mounted_path_absent":
            if any(marker in lower for marker in _NOT_FOUND_MARKERS):
                return "PASS"
            if response_text:
                return "FAIL"
            return "UNKNOWN"

        if check.kind == "env_literal":
            if probe_value in response_text:
                return "PASS"
            if response_text and not is_error:
                return "FAIL"
            if "akia" in lower or "tcp://" in lower or "/root" in lower or "/home/" in lower:
                return "FAIL"
            return "UNKNOWN"

        if check.kind == "env_path_literal":
            if probe_value in response_text:
                return "PASS"
            if "/root/" in lower or "/home/" in lower:
                return "FAIL"
            if any(marker in lower for marker in _NOT_FOUND_MARKERS):
                return "UNKNOWN"
            return "FAIL" if response_text else "UNKNOWN"

        if check.kind == "socket_absent":
            if any(marker in lower for marker in _NOT_FOUND_MARKERS):
                return "PASS"
            if response_text:
                return "FAIL"
            return "UNKNOWN"

        if check.kind == "bridge_blocked":
            if "172.17.0.1" in response_text or not is_error:
                return "FAIL"
            if "blocked" in lower or "not authorized" in lower or "policy" in lower:
                return "PASS"
            return "UNKNOWN"

        return "UNKNOWN"
