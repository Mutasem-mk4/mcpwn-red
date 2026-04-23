from __future__ import annotations

from typing import Any

import pytest
import yaml
from mcp.types import Tool

from mcpwn_red.attacks.yaml_injection import YAMLInjectionTester, YAML_FIXTURES
from tests.conftest import make_tool


class RejectingClient:
    def __init__(self, config: Any) -> None:
        self.config = config

    async def __aenter__(self) -> "RejectingClient":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    async def list_tools(self) -> list[Tool]:
        return []


class EnumeratingClient:
    tools_dir: Any = None

    def __init__(self, config: Any) -> None:
        self.config = config

    async def __aenter__(self) -> "EnumeratingClient":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    async def list_tools(self) -> list[Tool]:
        tools = []
        for fixture_path in self.tools_dir.glob("*.yaml"):
            payload = yaml.safe_load(fixture_path.read_text(encoding="utf-8"))
            tools.append(make_tool(payload["name"], description=payload["description"]))
        return tools


@pytest.mark.asyncio
async def test_yaml_module_passes_when_tool_not_loaded(
    monkeypatch: pytest.MonkeyPatch,
    client_config: Any,
    tmp_path: Any,
) -> None:
    monkeypatch.setattr("mcpwn_red.attacks.yaml_injection.MCPClient", RejectingClient)
    tester = YAMLInjectionTester(client_config, confirm_write=True, tools_dir=tmp_path)

    results = await tester.run()

    assert len(results) == len(YAML_FIXTURES)
    assert all(result.status == "PASS" for result in results)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_yaml_module_fails_when_fixture_is_exposed(
    monkeypatch: pytest.MonkeyPatch,
    client_config: Any,
    tmp_path: Any,
) -> None:
    EnumeratingClient.tools_dir = tmp_path
    monkeypatch.setattr("mcpwn_red.attacks.yaml_injection.MCPClient", EnumeratingClient)
    tester = YAMLInjectionTester(client_config, confirm_write=True, tools_dir=tmp_path)

    results = await tester.run()

    assert all(result.status == "FAIL" for result in results)
    assert "description=" in results[0].evidence

