from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcpwn_red.attacks.container_check import CHECKS, ContainerBoundaryChecker
from mcpwn_red.mcp_client import MCPClient
from mcpwn_red.policy import AssessmentPolicy, PolicyRule, evaluate_policy


@pytest.mark.asyncio
@pytest.mark.parametrize(("mode", "expected"), [("restricted", "PASS"), ("permissive", "FAIL")])
async def test_real_file_boundary_over_sdk_transport(
    tmp_path: Path, mode: str, expected: str
) -> None:
    (tmp_path / "inside" / "work").mkdir(parents=True)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0:fixture-only", encoding="utf-8")
    server = Path(__file__).parent / "fixtures" / "boundary_server.py"
    async with MCPClient(
        command=sys.executable, command_args=[str(server), str(tmp_path), mode]
    ) as client:
        probe = await ContainerBoundaryChecker().run_check(
            client, await client.list_tools(), CHECKS[0]
        )
    policy = AssessmentPolicy(
        name="Deny reads outside workspace", checks={"CHECK-01": PolicyRule(action="deny")}
    )
    judged = evaluate_policy(probe, policy)
    assert judged.status == expected
    assert judged.evidence_kind == "tool_response"
    assert evaluate_policy(probe, None).status == "UNKNOWN"
    if mode == "permissive":
        assert judged.evidence == (tmp_path / "etc" / "passwd").read_text()
        permitted = AssessmentPolicy(
            name="Permit fixture file", checks={"CHECK-01": PolicyRule(action="allow")}
        )
        assert evaluate_policy(probe, permitted).status == "PASS"
