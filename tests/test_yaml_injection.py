from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from mcpwn_red.attacks.yaml_injection import YAML_FIXTURES, YamlInjectionTester


@pytest.mark.asyncio
async def test_missing_executable_is_error_not_pass(tmp_path: Path) -> None:
    results = await YamlInjectionTester(command=str(tmp_path / "missing-mcpwn")).run()
    assert results
    assert all(result.status == "ERROR" for result in results)


@pytest.fixture
def isolated_mcpwn(tmp_path: Path) -> Path:
    executable = os.environ.get("MCPWN_TEST_COMMAND")
    if not executable:
        pytest.skip("Set MCPWN_TEST_COMMAND to run real MCPwn configuration tests")
    command = tmp_path / Path(executable).name
    shutil.copy2(executable, command)
    return command


@pytest.mark.asyncio
async def test_real_configuration_rejection_and_acceptance_preserve_user_files(
    isolated_mcpwn: Path,
) -> None:
    user_config = isolated_mcpwn.parent / "mcpwn.yaml"
    user_config.write_text("private user configuration", encoding="utf-8")
    results = await YamlInjectionTester(command=str(isolated_mcpwn), timeout=5).run()
    statuses = {result.id: result.status for result in results}
    assert statuses == {
        fixture.attack_id: "PASS" if fixture.name == "command_missing" else "FAIL"
        for fixture in YAML_FIXTURES
    }
    assert user_config.read_text(encoding="utf-8") == "private user configuration"


@pytest.mark.asyncio
async def test_non_mcp_executable_is_error_not_rejection(tmp_path: Path) -> None:
    import sys

    results = await YamlInjectionTester(command=sys.executable, timeout=1).run()
    assert all(result.status == "ERROR" for result in results)
