from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from mcpwn_red.mcp_client import MCPClient, MCPClientError


class FakeTransport:
    async def __aenter__(self) -> tuple[object, object]:
        return object(), object()

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None


class FakeSession:
    def __init__(self, read_stream: object, write_stream: object) -> None:
        self.read_stream = read_stream
        self.write_stream = write_stream

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    async def initialize(self) -> Any:
        return SimpleNamespace(serverInfo=SimpleNamespace(version="7.1"))

    async def list_tools(self) -> Any:
        tool = SimpleNamespace(
            model_dump=lambda **_: {
                "name": "nmap",
                "inputSchema": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                },
            }
        )
        return SimpleNamespace(tools=[tool])

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        read_timeout_seconds: Any,
    ) -> Any:
        return SimpleNamespace(isError=False, content=[SimpleNamespace(text="OK")])


@pytest.mark.asyncio
async def test_connect_list_and_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("mcpwn_red.mcp_client.stdio_client", lambda _server: FakeTransport())
    monkeypatch.setattr("mcpwn_red.mcp_client.ClientSession", FakeSession)
    client = MCPClient()
    await client.connect()
    tools = await client.list_tools()
    output = await client.call_tool("nmap", {"target": "127.0.0.1"})
    await client.disconnect()
    assert tools[0]["name"] == "nmap"
    assert output == "OK"


@pytest.mark.asyncio
async def test_connect_wraps_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenTransport:
        async def __aenter__(self) -> tuple[object, object]:
            raise FileNotFoundError("mcpwn")

        async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
            return None

    monkeypatch.setattr("mcpwn_red.mcp_client.stdio_client", lambda _server: BrokenTransport())
    client = MCPClient()
    with pytest.raises(MCPClientError):
        await client.connect()
