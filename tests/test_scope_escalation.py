from __future__ import annotations

from typing import Any

import pytest

from mcpwn_red.attacks.base import ToolReference
from mcpwn_red.attacks.scope_escalation import ESCALATION_CHAINS, ToolScopeEscalationTester
from tests.conftest import make_result


class BlockingEscalationClient:
    def __init__(self, config: Any) -> None:
        self.config = config
        self.call_count = 0

    async def __aenter__(self) -> "BlockingEscalationClient":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    async def list_tool_refs(self) -> list[ToolReference]:
        return [
            ToolReference("nmap", "", {"target": {"type": "string"}, "ports": {"type": "string"}}, ("target",)),
            ToolReference("gobuster", "", {"url": {"type": "string"}, "wordlist": {"type": "string"}, "threads": {"type": "string"}}, ("url", "wordlist")),
            ToolReference("sqlmap", "", {"url": {"type": "string"}}, ("url",)),
            ToolReference("metasploit", "", {"module": {"type": "string"}, "target": {"type": "string"}}, ("module",)),
            ToolReference("shell_exec", "", {"command": {"type": "string"}}, ("command",)),
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        self.call_count += 1
        if self.call_count % 2 == 1:
            return make_result(f"authorized call {name}", is_error=False)
        return make_result("blocked by policy", is_error=True)


class FailingEscalationClient(BlockingEscalationClient):
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        return make_result(f"executed {name}", is_error=False)


@pytest.mark.asyncio
async def test_scope_chains_pass_when_follow_on_steps_are_blocked(
    monkeypatch: pytest.MonkeyPatch,
    client_config: Any,
) -> None:
    monkeypatch.setattr("mcpwn_red.attacks.scope_escalation.MCPClient", BlockingEscalationClient)
    tester = ToolScopeEscalationTester(client_config)

    results = await tester.run()

    assert len(results) == len(ESCALATION_CHAINS)
    assert all(result.status == "PASS" for result in results)


@pytest.mark.asyncio
async def test_scope_chain_fails_when_escalation_executes(
    monkeypatch: pytest.MonkeyPatch,
    client_config: Any,
) -> None:
    monkeypatch.setattr("mcpwn_red.attacks.scope_escalation.MCPClient", FailingEscalationClient)
    tester = ToolScopeEscalationTester(client_config)

    results = await tester.run()

    assert any(result.status == "FAIL" for result in results)
