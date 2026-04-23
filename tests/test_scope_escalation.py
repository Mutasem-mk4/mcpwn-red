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
async def test_pass_when_step_two_is_blocked(mock_mcp_client: AsyncMock) -> None:
    tester = ScopeEscalationTester()
    mock_mcp_client.call_tool.side_effect = ["scan result", MCPClientError("blocked by policy")]
    result = await tester.run_chain(
        mock_mcp_client,
        await mock_mcp_client.list_tools(),
        CHAINS[0],
    )
    assert result.status == "PASS"


@pytest.mark.asyncio
async def test_fail_when_step_two_executes(mock_mcp_client: AsyncMock) -> None:
    tester = ScopeEscalationTester()
    mock_mcp_client.call_tool.side_effect = ["scan result", "step 2 executed"]
    result = await tester.run_chain(
        mock_mcp_client,
        await mock_mcp_client.list_tools(),
        CHAINS[0],
    )
    assert result.status == "FAIL"
