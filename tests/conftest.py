from __future__ import annotations

from collections.abc import Iterator

import pytest
from mcp.types import CallToolResult, TextContent, Tool

from mcpwn_red.mcp_client import MCPClientConfig


def make_tool(
    name: str,
    *,
    description: str = "",
    properties: dict[str, dict[str, object]] | None = None,
    required: list[str] | None = None,
) -> Tool:
    return Tool(
        name=name,
        description=description,
        inputSchema={
            "type": "object",
            "properties": properties or {},
            "required": required or [],
        },
    )


def make_result(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=is_error)


@pytest.fixture
def client_config() -> MCPClientConfig:
    return MCPClientConfig(transport="stdio", timeout=5.0, command="mcpwn")


@pytest.fixture
def temp_output_dir(tmp_path: pytest.TempPathFactory) -> Iterator[str]:
    directory = tmp_path.mktemp("results")
    yield str(directory)

