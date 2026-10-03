from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from mcpwn_red.attacks.scope_escalation import CHAINS, ScopeEscalationTester
from mcpwn_red.mcp_client import MCPClientError


@pytest.mark.asyncio
async def test_unknown_when_step_one_tool_missing(mock_mcp_client: AsyncMock) -> None:
    tester = ScopeEscalationTester()
    mock_mcp_client.list_tools.return_value = []
    results = await tester.run(mock_mcp_client)
    assert results[0].status == "UNKNOWN"


@pytest.mark.asyncio
async def test_tool_error_does_not_prove_policy_enforcement(mock_mcp_client: AsyncMock) -> None:
    tester = ScopeEscalationTester()
    mock_mcp_client.call_tool.side_effect = ["scan result", MCPClientError("blocked by policy")]
    result = await tester.run_chain(
        mock_mcp_client,
        await mock_mcp_client.list_tools(),
        CHAINS[0],
    )
    assert result.status == "ERROR"


@pytest.mark.asyncio
async def test_success_text_does_not_prove_step_two_execution(mock_mcp_client: AsyncMock) -> None:
    tester = ScopeEscalationTester()
    mock_mcp_client.call_tool.side_effect = ["scan result", "step 2 executed"]
    result = await tester.run_chain(
        mock_mcp_client,
        await mock_mcp_client.list_tools(),
        CHAINS[0],
    )
    assert result.status == "UNKNOWN"


@pytest.mark.asyncio
async def test_disconnect_during_step_two_is_error(mock_mcp_client: AsyncMock) -> None:
    mock_mcp_client.call_tool.side_effect = ["scan result", MCPClientError("connection lost")]
    result = await ScopeEscalationTester().run_chain(
        mock_mcp_client, await mock_mcp_client.list_tools(), CHAINS[0]
    )
    assert result.status == "ERROR"
