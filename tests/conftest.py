from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from mcpwn_red.attacks.base import AttackResult, ScanReport, summarize_results
from mcpwn_red.mcp_client import MCPClient


@pytest.fixture
def sample_tool_list() -> list[dict[str, object]]:
    return [
        {
            "name": "nmap",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "ports": {"type": "string"},
                },
                "required": ["target"],
            },
        },
        {
            "name": "gobuster",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "wordlist": {"type": "string"},
                },
                "required": ["url", "wordlist"],
            },
        },
        {
            "name": "ffuf",
            "inputSchema": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
        {
            "name": "curl",
            "inputSchema": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
        {
            "name": "sqlmap",
            "inputSchema": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
        {
            "name": "shell_exec",
            "inputSchema": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        },
        {
            "name": "metasploit",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "exploit": {"type": "string"},
                    "RHOSTS": {"type": "string"},
                },
                "required": ["exploit", "RHOSTS"],
            },
        },
        {
            "name": "poisoned_output",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    ]


@pytest.fixture
def mock_mcp_client(sample_tool_list: list[dict[str, object]]) -> AsyncMock:
    client = AsyncMock(spec=MCPClient)
    client.list_tools = AsyncMock(return_value=sample_tool_list)
    client.call_tool = AsyncMock(return_value="OK")
    client.server_version = "7.1"
    return client


@pytest.fixture
def tmp_tools_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "tools"
    directory.mkdir()
    return directory


@pytest.fixture
def sample_scan_report() -> ScanReport:
    results = [
        AttackResult(
            id="TEST-01",
            name="pass_case",
            module="yaml",
            status="PASS",
            severity="low",
            evidence="sanitized",
            duration_ms=10,
            recommendation="Keep schema validation enabled.",
        ),
        AttackResult(
            id="TEST-02",
            name="fail_case",
            module="container",
            status="FAIL",
            severity="high",
            evidence="root:x:0:0",
            duration_ms=12,
            recommendation="Reject path traversal input.",
        ),
        AttackResult(
            id="TEST-03",
            name="unknown_case",
            module="scope",
            status="UNKNOWN",
            severity="medium",
            evidence="tool unavailable",
            duration_ms=8,
            recommendation="Install the missing tool or skip the chain.",
        ),
    ]
    return ScanReport(
        version="0.1.0",
        timestamp=datetime.now(timezone.utc),
        mcpwn_version="7.1",
        transport="stdio",
        results=results,
        summary=summarize_results(results),
    )
