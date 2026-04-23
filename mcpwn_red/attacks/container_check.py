from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any

from mcpwn_red.attacks.base import AttackResult, build_arguments, build_result, find_tool
from mcpwn_red.mcp_client import MCPClientError


@dataclass(frozen=True)
class ContainerCheck:
    attack_id: str
    name: str
    severity: str
    description: str
    recommendation: str


CHECKS: tuple[ContainerCheck, ...] = (
    ContainerCheck(
        attack_id="CHECK-01",
        name="path_traversal_etc_passwd",
        severity="critical",
        description="Probe nmap with ../../etc/passwd to detect file-content traversal.",
        recommendation="Validate scan targets as hosts or IPs before passing them to nmap.",
    ),
    ContainerCheck(
        attack_id="CHECK-02",
        name="path_traversal_shadow",
        severity="high",
        description="Probe gobuster with /host/etc/shadow as a wordlist path.",
        recommendation="Restrict tool file inputs to a dedicated in-container workspace.",
    ),
    ContainerCheck(
        attack_id="CHECK-03",
        name="env_var_docker_host",
        severity="high",
        description="Verify $DOCKER_HOST is not expanded by a tool call.",
        recommendation="Pass arguments without shell expansion and scrub DOCKER_HOST.",
    ),
    ContainerCheck(
        attack_id="CHECK-04",
        name="env_var_aws_secret",
        severity="critical",
        description="Verify $AWS_SECRET_ACCESS_KEY is not expanded by a tool call.",
        recommendation="Clear cloud credentials from the container environment.",
    ),
    ContainerCheck(
        attack_id="CHECK-05",
        name="docker_socket_reachable",
        severity="critical",
        description="Check whether /var/run/docker.sock is visible to a legitimate tool.",
        recommendation="Never mount the Docker socket into MCPwn tool containers.",
    ),
    ContainerCheck(
        attack_id="CHECK-06",
        name="bridge_network_reachable",
        severity="high",
        description="Probe the default Docker bridge gateway at 172.17.0.1.",
        recommendation="Filter container egress to bridge and host-management networks.",
    ),
    ContainerCheck(
        attack_id="CHECK-07",
        name="host_proc_readable",
        severity="high",
        description="Attempt to read /proc/1/cmdline through a legitimate tool argument.",
        recommendation="Harden procfs visibility and reject raw host-path arguments.",
    ),
    ContainerCheck(
        attack_id="CHECK-08",
        name="workspace_escape_upward",
        severity="medium",
        description="Attempt upward path traversal outside the intended workspace.",
        recommendation="Normalize and reject upward-relative paths before tool execution.",
    ),
    ContainerCheck(
        attack_id="CHECK-09",
        name="inter_container_localhost",
        severity="high",
        description="Scan localhost for Docker daemon ports 2375 and 2376.",
        recommendation="Ensure internal daemon ports are closed to tool containers.",
    ),
    ContainerCheck(
        attack_id="CHECK-10",
        name="sensitive_env_HOME",
        severity="medium",
        description="Verify $HOME remains literal rather than expanding to a real path.",
        recommendation="Prevent shell expansion and sanitize HOME before tool execution.",
    ),
)


class ContainerBoundaryChecker:
    module = "container"

    def __init__(self) -> None:
        self._checks = CHECKS

    @classmethod
    def catalog(cls) -> list[dict[str, str]]:
        return [
            {
                "id": check.attack_id,
                "module": cls.module,
                "severity": check.severity,
                "description": check.description,
            }
            for check in CHECKS
        ]

    async def run(self, client: Any) -> list[AttackResult]:
        tools = await client.list_tools()
        results: list[AttackResult] = []
        for check in self._checks:
            results.append(await self.run_check(client, tools, check))
        return results

    async def run_check(
        self,
        client: Any,
        tools: list[dict[str, Any]],
        check: ContainerCheck,
    ) -> AttackResult:
        started_at = perf_counter()
        try:
            if check.attack_id == "CHECK-01":
                tool = find_tool(tools, ("nmap",))
                if tool is None:
                    return self._unknown(check, started_at, "nmap unavailable for traversal probe.")
                response = await client.call_tool(
                    tool["name"],
                    build_arguments(tool, {"target": "../../etc/passwd", "ports": "80"}),
                )
                status = "FAIL" if "root:" in response else "PASS"
                return self._result(check, started_at, status, response)

            if check.attack_id == "CHECK-02":
                tool = find_tool(tools, ("gobuster",))
                if tool is None:
                    return self._unknown(check, started_at, "gobuster unavailable for path probe.")
                response = await client.call_tool(
                    tool["name"],
                    build_arguments(
                        tool,
                        {"url": "http://127.0.0.1", "wordlist": "/host/etc/shadow"},
                    ),
                )
                lower = response.lower()
                status = "PASS" if "path" in lower or "no such file" in lower else "FAIL"
                return self._result(check, started_at, status, response)

            if check.attack_id == "CHECK-03":
                return await self._run_literal_env_check(
                    client,
                    tools,
                    check,
                    started_at,
                    variable="$DOCKER_HOST",
                )

            if check.attack_id == "CHECK-04":
                return await self._run_literal_env_check(
                    client,
                    tools,
                    check,
                    started_at,
                    variable="$AWS_SECRET_ACCESS_KEY",
                )

            if check.attack_id == "CHECK-05":
                tool = find_tool(tools, ("shell_exec", "shell", "exec", "command"))
                if tool is None:
                    tool = find_tool(tools, ("gobuster",))
                if tool is None:
                    return self._unknown(
                        check,
                        started_at,
                        "No suitable tool for docker.sock probe.",
                    )
                desired = (
                    {"command": "ls /var/run/docker.sock"}
                    if "shell" in tool["name"] or "exec" in tool["name"]
                    else {"url": "http://127.0.0.1", "wordlist": "/var/run/docker.sock"}
                )
                response = await client.call_tool(tool["name"], build_arguments(tool, desired))
                lower = response.lower()
                status = (
                    "PASS"
                    if "no such file" in lower or "permission denied" in lower
                    else "FAIL"
                )
                return self._result(check, started_at, status, response)

            if check.attack_id == "CHECK-06":
                tool = find_tool(tools, ("nmap",))
                if tool is None:
                    return self._unknown(check, started_at, "nmap unavailable for bridge probe.")
                response = await client.call_tool(
                    tool["name"],
                    build_arguments(tool, {"target": "172.17.0.1", "ports": "1-1024"}),
                )
                lower = response.lower()
                status = "FAIL" if "open" in lower and "172.17.0.1" in lower else "PASS"
                return self._result(check, started_at, status, response)

            if check.attack_id == "CHECK-07":
                tool = find_tool(tools, ("gobuster", "shell_exec", "shell", "exec"))
                if tool is None:
                    return self._unknown(check, started_at, "No suitable tool for /proc probe.")
                desired = (
                    {"command": "cat /proc/1/cmdline"}
                    if "shell" in tool["name"] or "exec" in tool["name"]
                    else {"url": "http://127.0.0.1", "wordlist": "/proc/1/cmdline"}
                )
                response = await client.call_tool(tool["name"], build_arguments(tool, desired))
                lower = response.lower()
                status = "FAIL" if "python" in lower or "systemd" in lower else "PASS"
                return self._result(check, started_at, status, response)

            if check.attack_id == "CHECK-08":
                tool = find_tool(tools, ("gobuster", "shell_exec", "shell", "exec"))
                if tool is None:
                    return self._unknown(
                        check,
                        started_at,
                        "No suitable tool for workspace escape.",
                    )
                desired = (
                    {"command": "ls ../../../home"}
                    if "shell" in tool["name"] or "exec" in tool["name"]
                    else {"url": "http://127.0.0.1", "wordlist": "../../../home"}
                )
                response = await client.call_tool(tool["name"], build_arguments(tool, desired))
                lower = response.lower()
                status = "FAIL" if "/home" in lower and "invalid" not in lower else "PASS"
                return self._result(check, started_at, status, response)

            if check.attack_id == "CHECK-09":
                tool = find_tool(tools, ("nmap",))
                if tool is None:
                    return self._unknown(check, started_at, "nmap unavailable for localhost probe.")
                response = await client.call_tool(
                    tool["name"],
                    build_arguments(tool, {"target": "localhost", "ports": "2375,2376"}),
                )
                lower = response.lower()
                status = "FAIL" if "2375/tcp open" in lower or "2376/tcp open" in lower else "PASS"
                return self._result(check, started_at, status, response)

            tool = find_tool(tools, ("nmap", "gobuster", "ffuf", "curl", "sqlmap"))
            if tool is None:
                return self._unknown(check, started_at, "No suitable tool for HOME literal probe.")
            response = await client.call_tool(
                tool["name"],
                build_arguments(tool, {"target": "$HOME", "url": "$HOME"}),
            )
            lower = response.lower()
            status = "FAIL" if "/home/" in lower or "\\users\\" in lower else "PASS"
            return self._result(check, started_at, status, response)
        except MCPClientError as exc:
            return self._result(check, started_at, "PASS", str(exc))

    async def _run_literal_env_check(
        self,
        client: Any,
        tools: list[dict[str, Any]],
        check: ContainerCheck,
        started_at: float,
        *,
        variable: str,
    ) -> AttackResult:
        tool = find_tool(tools, ("nmap", "gobuster", "ffuf", "curl", "sqlmap"))
        if tool is None:
            return self._unknown(
                check,
                started_at,
                f"No suitable tool for {variable} literal check.",
            )
        response = await client.call_tool(
            tool["name"],
            build_arguments(tool, {"target": variable, "url": variable}),
        )
        lower = response.lower()
        status = (
            "FAIL"
            if variable not in response and ("tcp://" in lower or "/" in response)
            else "PASS"
        )
        return self._result(check, started_at, status, response)

    def _unknown(
        self,
        check: ContainerCheck,
        started_at: float,
        evidence: str,
    ) -> AttackResult:
        return self._result(check, started_at, "UNKNOWN", evidence)

    def _result(
        self,
        check: ContainerCheck,
        started_at: float,
        status: str,
        evidence: str,
    ) -> AttackResult:
        return build_result(
            attack_id=check.attack_id,
            name=check.name,
            module=self.module,
            status=status,
            severity=check.severity,
            evidence=evidence,
            started_at=started_at,
            recommendation=check.recommendation,
        )
