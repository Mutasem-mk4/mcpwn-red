from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from mcpwn_red.attacks.container_check import CHECKS, ContainerBoundaryChecker


@pytest.mark.asyncio
async def test_path_traversal_fail(
    mock_mcp_client: AsyncMock,
    sample_tool_list: list[dict[str, object]],
) -> None:
    checker = ContainerBoundaryChecker()
    mock_mcp_client.call_tool.return_value = "root:x:0:0"
    result = await checker.run_check(mock_mcp_client, sample_tool_list, CHECKS[0])
    assert result.status == "FAIL"


@pytest.mark.asyncio
async def test_path_traversal_pass(
    mock_mcp_client: AsyncMock,
    sample_tool_list: list[dict[str, object]],
) -> None:
    checker = ContainerBoundaryChecker()
    mock_mcp_client.call_tool.return_value = "invalid path"
    result = await checker.run_check(mock_mcp_client, sample_tool_list, CHECKS[0])
    assert result.status == "PASS"


@pytest.mark.asyncio
async def test_docker_socket_absent_is_pass(
    mock_mcp_client: AsyncMock,
    sample_tool_list: list[dict[str, object]],
) -> None:
    checker = ContainerBoundaryChecker()
    mock_mcp_client.call_tool.return_value = "No such file"
    result = await checker.run_check(mock_mcp_client, sample_tool_list, CHECKS[4])
    assert result.status == "PASS"


@pytest.mark.asyncio
async def test_all_10_checks_run(mock_mcp_client: AsyncMock) -> None:
    checker = ContainerBoundaryChecker()
    results = await checker.run(mock_mcp_client)
    assert len(results) == 10
