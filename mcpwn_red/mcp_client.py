"""Thin MCP SDK wrapper used by the attack modules.

Protocol notes:
  - A real stdio tool call is JSON-RPC 2.0 over newline-delimited messages:
    {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"nmap","arguments":{"target":"127.0.0.1","ports":"80"}}}
  - Tool discovery is:
    {"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}}
  - A typical tools/call result is:
    {"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"..."}],"isError":false}}
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal

import httpx
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import McpError
from mcp.types import CallToolResult, Implementation, InitializeResult, ListToolsResult, Tool

from mcpwn_red import __version__
from mcpwn_red.attacks.base import ToolReference


class MCPClientError(RuntimeError):
    """User-facing transport or protocol failure."""


@dataclass(frozen=True, slots=True)
class MCPClientConfig:
    transport: Literal["stdio", "sse"]
    timeout: float = 30.0
    command: str = "mcpwn"
    command_args: list[str] = field(default_factory=list)
    url: str | None = None
    env: dict[str, str] | None = None
    headers: dict[str, str] | None = None


class MCPClient:
    """Async context manager for a single initialized MCP session."""

    def __init__(self, config: MCPClientConfig) -> None:
        self.config = config
        self._transport_cm: Any | None = None
        self._transport_exit: Any | None = None
        self._session_cm: ClientSession | None = None
        self._session: ClientSession | None = None
        self._initialize_result: InitializeResult | None = None

    @property
    def initialize_result(self) -> InitializeResult:
        if self._initialize_result is None:
            msg = "MCP client session has not been initialized"
            raise MCPClientError(msg)
        return self._initialize_result

    @property
    def server_name(self) -> str | None:
        server_info = self.initialize_result.serverInfo
        return server_info.name if server_info is not None else None

    @property
    def server_version(self) -> str | None:
        server_info = self.initialize_result.serverInfo
        return server_info.version if server_info is not None else None

    async def __aenter__(self) -> "MCPClient":
        try:
            if self.config.transport == "stdio":
                server_parameters = StdioServerParameters(
                    command=self.config.command,
                    args=self.config.command_args,
                    env=self.config.env,
                )
                self._transport_cm = stdio_client(server_parameters)
            else:
                if not self.config.url:
                    msg = "SSE transport requires --url"
                    raise MCPClientError(msg)
                self._transport_cm = sse_client(
                    self.config.url,
                    headers=self.config.headers,
                    timeout=self.config.timeout,
                    sse_read_timeout=max(self.config.timeout, 30.0),
                )

            read_stream, write_stream = await self._transport_cm.__aenter__()
            self._transport_exit = self._transport_cm.__aexit__
            self._session_cm = ClientSession(
                read_stream,
                write_stream,
                client_info=Implementation(name="mcpwn-red", version=__version__),
            )
            self._session = await self._session_cm.__aenter__()
            self._initialize_result = await asyncio.wait_for(
                self._session.initialize(),
                timeout=self.config.timeout,
            )
            return self
        except FileNotFoundError as exc:
            raise MCPClientError(
                f"Unable to start MCPwn command {self.config.command!r}: {exc.strerror or exc}"
            ) from exc
        except asyncio.TimeoutError as exc:
            raise MCPClientError(
                f"MCPwn did not initialize within {self.config.timeout:.0f} seconds"
            ) from exc
        except httpx.HTTPError as exc:
            raise MCPClientError(f"Unable to reach MCPwn over SSE: {exc}") from exc
        except (McpError, OSError, RuntimeError, ValueError) as exc:
            raise MCPClientError(f"MCP session setup failed: {exc}") from exc

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._session_cm is not None:
            await self._session_cm.__aexit__(exc_type, exc, tb)
        if self._transport_exit is not None:
            await self._transport_exit(exc_type, exc, tb)
        self._session = None
        self._session_cm = None
        self._transport_cm = None
        self._transport_exit = None
        self._initialize_result = None

    async def list_tools(self) -> list[Tool]:
        if self._session is None:
            msg = "MCP session is not active"
            raise MCPClientError(msg)
        try:
            response: ListToolsResult = await asyncio.wait_for(
                self._session.list_tools(),
                timeout=self.config.timeout,
            )
            return list(response.tools)
        except asyncio.TimeoutError as exc:
            raise MCPClientError(
                f"MCPwn tools/list timed out after {self.config.timeout:.0f} seconds"
            ) from exc
        except (McpError, RuntimeError, ValueError) as exc:
            raise MCPClientError(f"MCPwn tools/list failed: {exc}") from exc

    async def list_tool_refs(self) -> list[ToolReference]:
        return [ToolReference.from_tool(tool) for tool in await self.list_tools()]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> CallToolResult:
        if self._session is None:
            msg = "MCP session is not active"
            raise MCPClientError(msg)
        try:
            return await self._session.call_tool(
                name,
                arguments=arguments or {},
                read_timeout_seconds=timedelta(seconds=self.config.timeout),
            )
        except asyncio.TimeoutError as exc:
            raise MCPClientError(
                f"MCPwn tools/call for {name!r} timed out after {self.config.timeout:.0f} seconds"
            ) from exc
        except (McpError, RuntimeError, ValueError) as exc:
            raise MCPClientError(f"MCPwn tools/call for {name!r} failed: {exc}") from exc

    async def probe(self) -> dict[str, Any]:
        tools = await self.list_tools()
        return {
            "server_name": self.server_name,
            "server_version": self.server_version,
            "tool_count": len(tools),
            "transport": self.config.transport,
        }
