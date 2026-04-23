from __future__ import annotations

from typing import Any

import pytest

from mcpwn_red.attacks.base import ToolReference
from mcpwn_red.attacks.output_injection import OUTPUT_PAYLOADS, OutputInjectionTester
from tests.conftest import make_result


class EchoClient:
    def __init__(self, config: Any) -> None:
        self.config = config

    async def __aenter__(self) -> "EchoClient":
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
            )
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        return make_result(str(arguments["target"]), is_error=False)


class BlockingClient(EchoClient):
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        return make_result("invalid target syntax", is_error=True)


@pytest.mark.asyncio
async def test_output_payloads_fail_when_echoed(
    monkeypatch: pytest.MonkeyPatch,
    client_config: Any,
) -> None:
    monkeypatch.setattr("mcpwn_red.attacks.output_injection.MCPClient", EchoClient)
    tester = OutputInjectionTester(client_config)

    results = await tester.run()

    assert len(results) == len(OUTPUT_PAYLOADS)
    assert all(result.status == "FAIL" for result in results)


@pytest.mark.asyncio
async def test_output_payloads_pass_when_blocked(
    monkeypatch: pytest.MonkeyPatch,
    client_config: Any,
) -> None:
    monkeypatch.setattr("mcpwn_red.attacks.output_injection.MCPClient", BlockingClient)
    tester = OutputInjectionTester(client_config)

    results = await tester.run()

    assert all(result.status == "PASS" for result in results)

