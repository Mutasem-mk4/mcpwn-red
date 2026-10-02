from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from mcpwn_red.attacks.container_check import CHECKS, ContainerBoundaryChecker
from mcpwn_red.mcp_client import MCPClientError


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


@pytest.mark.asyncio
async def test_transport_failure_never_passes_container_checks(mock_mcp_client: AsyncMock) -> None:
    mock_mcp_client.call_tool.side_effect = MCPClientError("connection lost")
    results = await ContainerBoundaryChecker().run(mock_mcp_client)
    assert all(result.status == "ERROR" for result in results)


@pytest.mark.asyncio
async def test_uninformative_success_does_not_prove_isolation(mock_mcp_client: AsyncMock) -> None:
    mock_mcp_client.call_tool.return_value = "OK"
    results = await ContainerBoundaryChecker().run(mock_mcp_client)
    assert all(result.status == "UNKNOWN" for result in results)
