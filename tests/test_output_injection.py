from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from mcpwn_red.attacks.output_injection import PAYLOADS, OutputInjectionSimulator
from mcpwn_red.mcp_client import MCPClientError


@pytest.mark.asyncio
async def test_payload_01_detected(mock_mcp_client: AsyncMock) -> None:
    simulator = OutputInjectionSimulator()
    mock_mcp_client.call_tool.return_value = PAYLOADS[0].payload
    result = await simulator.run_payload(PAYLOADS[0], mock_mcp_client)
    assert result.status == "FAIL"


@pytest.mark.asyncio
async def test_payload_01_sanitized(mock_mcp_client: AsyncMock) -> None:
    simulator = OutputInjectionSimulator()
    mock_mcp_client.call_tool.return_value = "sanitized output"
    result = await simulator.run_payload(PAYLOADS[0], mock_mcp_client)
    assert result.status == "PASS"


@pytest.mark.asyncio
async def test_unknown_when_tool_missing(mock_mcp_client: AsyncMock) -> None:
    simulator = OutputInjectionSimulator()
    mock_mcp_client.call_tool.side_effect = MCPClientError("tool not found")
    result = await simulator.run_payload(PAYLOADS[0], mock_mcp_client)
    assert result.status == "UNKNOWN"


def test_all_12_payloads_covered() -> None:
    assert len(PAYLOADS) == 12
