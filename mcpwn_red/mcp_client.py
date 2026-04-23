from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any, Literal

import httpx
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import McpError


class MCPClientError(RuntimeError):
    pass


class MCPClient:
    def __init__(
        self,
        *,
        transport: Literal["stdio", "sse"] = "stdio",
        url: str | None = None,
        timeout: int = 30,
        command: str = "mcpwn",
        command_args: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.transport = transport
        self.url = url
        self.timeout = timeout
        self.command = command
        self.command_args = command_args or []
        self.env = env
        self._transport_cm: Any | None = None
        self._transport_exit: Any | None = None
        self._session_cm: ClientSession | None = None
        self._session: ClientSession | None = None
        self._server_version: str | None = None

    @property
    def server_version(self) -> str | None:
        return self._server_version

    async def __aenter__(self) -> MCPClient:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.disconnect()

    async def connect(self) -> None:
        if self._session is not None:
            return
        try:
            if self.transport == "stdio":
                server = StdioServerParameters(
                    command=self.command,
                    args=self.command_args,
                    env=self.env,
                )
                self._transport_cm = stdio_client(server)
            else:
                if not self.url:
                    raise MCPClientError("MCPwn is unreachable: SSE transport requires --url")
                self._transport_cm = sse_client(
                    self.url,
                    timeout=float(self.timeout),
                    sse_read_timeout=max(float(self.timeout), 30.0),
                )
            read_stream, write_stream = await self._transport_cm.__aenter__()
            self._transport_exit = self._transport_cm.__aexit__
            self._session_cm = ClientSession(read_stream, write_stream)
            self._session = await self._session_cm.__aenter__()
            result = await asyncio.wait_for(self._session.initialize(), timeout=self.timeout)
            if result.serverInfo is not None:
                self._server_version = result.serverInfo.version
        except FileNotFoundError as exc:
            await self.disconnect()
            raise MCPClientError(f"MCPwn is unreachable: {exc}") from exc
        except (httpx.HTTPError, McpError, OSError, RuntimeError, TimeoutError, ValueError) as exc:
            await self.disconnect()
            raise MCPClientError(f"MCPwn is unreachable: {exc}") from exc

    async def disconnect(self) -> None:
        if self._session_cm is not None:
            try:
                await self._session_cm.__aexit__(None, None, None)
            except (McpError, OSError, RuntimeError):
                pass
        if self._transport_exit is not None:
            try:
                await self._transport_exit(None, None, None)
            except (McpError, OSError, RuntimeError):
                pass
        self._session_cm = None
        self._session = None
        self._transport_cm = None
        self._transport_exit = None

    async def list_tools(self) -> list[dict[str, Any]]:
        session = self._require_session()
        try:
            result = await asyncio.wait_for(session.list_tools(), timeout=self.timeout)
            return [
                tool.model_dump(by_alias=True, exclude_none=True)
                if hasattr(tool, "model_dump")
                else dict(tool)
                for tool in result.tools
            ]
        except (McpError, OSError, RuntimeError, TimeoutError, ValueError) as exc:
            raise MCPClientError(f"MCPwn is unreachable: {exc}") from exc

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        session = self._require_session()
        try:
            result = await session.call_tool(
                name,
                arguments=arguments,
                read_timeout_seconds=timedelta(seconds=self.timeout),
            )
        except (McpError, OSError, RuntimeError, TimeoutError, ValueError) as exc:
            raise MCPClientError(f"MCPwn is unreachable: {exc}") from exc
        if result.isError:
            raise MCPClientError(f"MCPwn is unreachable: tool call failed for {name}")
        if not result.content:
            raise MCPClientError(f"MCPwn is unreachable: empty response for {name}")
        first_block = result.content[0]
        text_value = getattr(first_block, "text", None)
        if isinstance(text_value, str):
            return text_value
        if isinstance(first_block, dict):
            dict_text = first_block.get("text")
            if isinstance(dict_text, str):
                return dict_text
        return str(first_block)

    def _require_session(self) -> ClientSession:
        if self._session is None:
            raise MCPClientError("MCPwn is unreachable: client is not connected")
        return self._session
