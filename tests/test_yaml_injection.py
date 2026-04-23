from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from mcpwn_red.attacks.yaml_injection import YAML_FIXTURES, YamlInjectionTester


@pytest.mark.asyncio
async def test_bash_exec_fixture_written(
    mock_mcp_client: AsyncMock,
    tmp_tools_dir: Path,
) -> None:
    tester = YamlInjectionTester(tmp_tools_dir)
    fixture = YAML_FIXTURES[0]
    fixture_path = tmp_tools_dir / fixture.file_name
    seen = {"exists": False}

    async def list_tools_side_effect() -> list[dict[str, str]]:
        seen["exists"] = fixture_path.exists()
        return []

    mock_mcp_client.list_tools.side_effect = list_tools_side_effect
    await tester.run_fixture(mock_mcp_client, fixture)
    assert seen["exists"] is True


@pytest.mark.asyncio
async def test_bash_exec_fixture_removed(
    mock_mcp_client: AsyncMock,
    tmp_tools_dir: Path,
) -> None:
    tester = YamlInjectionTester(tmp_tools_dir)
    fixture = YAML_FIXTURES[0]
    fixture_path = tmp_tools_dir / fixture.file_name
    await tester.run_fixture(mock_mcp_client, fixture)
    assert fixture_path.exists() is False


@pytest.mark.asyncio
async def test_hidden_instruction_fail(
    mock_mcp_client: AsyncMock,
    tmp_tools_dir: Path,
) -> None:
    tester = YamlInjectionTester(tmp_tools_dir)
    fixture = next(item for item in YAML_FIXTURES if item.name == "hidden_instruction")
    mock_mcp_client.list_tools.return_value = [{"name": "hidden_instruction"}]
    result = await tester.run_fixture(mock_mcp_client, fixture)
    assert result.status == "FAIL"


@pytest.mark.asyncio
async def test_schema_missing_pass(
    mock_mcp_client: AsyncMock,
    tmp_tools_dir: Path,
) -> None:
    tester = YamlInjectionTester(tmp_tools_dir)
    fixture = next(item for item in YAML_FIXTURES if item.name == "schema_missing")
    mock_mcp_client.list_tools.return_value = [{"name": "nmap"}]
    result = await tester.run_fixture(mock_mcp_client, fixture)
    assert result.status == "PASS"


@pytest.mark.asyncio
async def test_result_has_evidence(
    mock_mcp_client: AsyncMock,
    tmp_tools_dir: Path,
) -> None:
    tester = YamlInjectionTester(tmp_tools_dir)
    results = await tester.run(mock_mcp_client)
    assert all(isinstance(result.evidence, str) and result.evidence for result in results)


@pytest.mark.asyncio
async def test_all_fixtures_produce_results(
    mock_mcp_client: AsyncMock,
    tmp_tools_dir: Path,
) -> None:
    tester = YamlInjectionTester(tmp_tools_dir)
    results = await tester.run(mock_mcp_client)
    assert len(results) == 8
