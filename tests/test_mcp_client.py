from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from mcp.types import Implementation, InitializeResult, ListToolsResult, ServerCapabilities, ToolsCapability

from mcpwn_red.mcp_client import MCPClient, MCPClientConfig, MCPClientError
from tests.conftest import make_tool


class FakeTransport:
    async def __aenter__(self) -> tuple[str, str]:
        return ("read", "write")

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None


@dataclass
class FakeSession:
    read_stream: Any
    write_stream: Any
    client_info: Any | None = None

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    async def initialize(self) -> InitializeResult:
        return InitializeResult(
            protocolVersion="2025-06-18",
            capabilities=ServerCapabilities(tools=ToolsCapability(listChanged=True)),
            serverInfo=Implementation(name="mcpwn", version="7.1"),
            instructions="",
        )

    async def list_tools(self) -> ListToolsResult:
        return ListToolsResult(
            tools=[make_tool("nmap", properties={"target": {"type": "string"}}, required=["target"])]
        )


@pytest.mark.asyncio
async def test_probe_uses_initialized_session(monkeypatch: pytest.MonkeyPatch, client_config: MCPClientConfig) -> None:
    monkeypatch.setattr("mcpwn_red.mcp_client.stdio_client", lambda params: FakeTransport())
    monkeypatch.setattr("mcpwn_red.mcp_client.ClientSession", FakeSession)

    async with MCPClient(client_config) as client:
        probe = await client.probe()

    assert probe["server_name"] == "mcpwn"
    assert probe["server_version"] == "7.1"
    assert probe["tool_count"] == 1


@pytest.mark.asyncio
async def test_sse_requires_url() -> None:
    with pytest.raises(MCPClientError):
        async with MCPClient(MCPClientConfig(transport="sse", timeout=5.0)):
            pass

