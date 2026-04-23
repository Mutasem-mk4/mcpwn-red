from __future__ import annotations

from typing import Any

import pytest

from mcpwn_red.attacks.base import ToolReference
from mcpwn_red.attacks.container_check import BOUNDARY_CHECKS, ContainerBoundaryChecker
from tests.conftest import make_result


class SafeBoundaryClient:
    def __init__(self, config: Any) -> None:
        self.config = config

    async def __aenter__(self) -> "SafeBoundaryClient":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    async def list_tool_refs(self) -> list[ToolReference]:
        return [
            ToolReference(
                name="nmap",
                description="",
                properties={"target": {"type": "string"}, "ports": {"type": "string"}},
                required=("target",),
            ),
            ToolReference(
                name="gobuster",
                description="",
                properties={
                    "url": {"type": "string"},
                    "wordlist": {"type": "string"},
                    "threads": {"type": "string"},
                },
                required=("url", "wordlist"),
            ),
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if name == "nmap":
            target = str(arguments["target"])
            if target == "172.17.0.1":
                return make_result("blocked by policy", is_error=True)
            return make_result(f"failed to resolve {target}", is_error=True)
        wordlist = str(arguments["wordlist"])
        return make_result(f"wordlist not found: {wordlist}", is_error=True)


class UnsafeBoundaryClient(SafeBoundaryClient):
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if name == "gobuster" and str(arguments["wordlist"]) == "/var/run/docker.sock":
            return make_result("opened /var/run/docker.sock", is_error=False)
        return await super().call_tool(name, arguments)


@pytest.mark.asyncio
async def test_container_checks_pass_when_probes_are_blocked(
    monkeypatch: pytest.MonkeyPatch,
    client_config: Any,
) -> None:
    monkeypatch.setattr("mcpwn_red.attacks.container_check.MCPClient", SafeBoundaryClient)
    tester = ContainerBoundaryChecker(client_config)

    results = await tester.run()

    assert len(results) == len(BOUNDARY_CHECKS)
    assert all(result.status == "PASS" for result in results)


@pytest.mark.asyncio
async def test_container_check_detects_socket_exposure(
    monkeypatch: pytest.MonkeyPatch,
    client_config: Any,
) -> None:
    monkeypatch.setattr("mcpwn_red.attacks.container_check.MCPClient", UnsafeBoundaryClient)
    tester = ContainerBoundaryChecker(client_config)

    results = await tester.run()

    socket_result = next(result for result in results if result.id == "CNT-06")
    assert socket_result.status == "FAIL"

