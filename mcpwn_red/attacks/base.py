from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Literal

from pydantic import BaseModel, Field


class AttackResult(BaseModel):
    id: str
    name: str
    module: str
    status: Literal["PASS", "FAIL", "UNKNOWN", "ERROR"]
    severity: Literal["critical", "high", "medium", "low"]
    evidence: str
    duration_ms: int
    recommendation: str


class ScanReport(BaseModel):
    tool: str = "mcpwn-red"
    version: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    mcpwn_version: str | None
    transport: str
    results: list[AttackResult]
    summary: dict[str, int]


class AttackBase(ABC):
    id: str
    name: str
    module: str
    severity: str
    description: str

    @abstractmethod
    async def run(self, client: Any) -> AttackResult:
        raise NotImplementedError


def summarize_results(results: list[AttackResult]) -> dict[str, int]:
    return {
        "PASS": sum(result.status == "PASS" for result in results),
        "FAIL": sum(result.status == "FAIL" for result in results),
        "UNKNOWN": sum(result.status == "UNKNOWN" for result in results),
        "ERROR": sum(result.status == "ERROR" for result in results),
    }


def build_result(
    *,
    attack_id: str,
    name: str,
    module: str,
    status: str,
    severity: str,
    evidence: str,
    started_at: float,
    recommendation: str,
) -> AttackResult:
    return AttackResult(
        id=attack_id,
        name=name,
        module=module,
        status=status,
        severity=severity,
        evidence=evidence,
        duration_ms=max(1, int((perf_counter() - started_at) * 1000)),
        recommendation=recommendation,
    )


def tool_name(tool: dict[str, Any]) -> str:
    name = tool.get("name")
    return name if isinstance(name, str) else ""


def tool_properties(tool: dict[str, Any]) -> dict[str, Any]:
    input_schema = tool.get("inputSchema")
    if not isinstance(input_schema, dict):
        return {}
    properties = input_schema.get("properties")
    return properties if isinstance(properties, dict) else {}


def tool_required(tool: dict[str, Any]) -> list[str]:
    input_schema = tool.get("inputSchema")
    if not isinstance(input_schema, dict):
        return []
    required = input_schema.get("required")
    if not isinstance(required, list):
        return []
    return [item for item in required if isinstance(item, str)]


def find_tool(tools: list[dict[str, Any]], candidates: tuple[str, ...]) -> dict[str, Any] | None:
    normalized_candidates = {candidate.lower() for candidate in candidates}
    for tool in tools:
        candidate_name = tool_name(tool).lower()
        if candidate_name in normalized_candidates:
            return tool
    for tool in tools:
        candidate_name = tool_name(tool).lower()
        if any(candidate in candidate_name for candidate in normalized_candidates):
            return tool
    return None


def build_arguments(tool: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    aliases = {
        "target": ("target", "host", "hostname", "address", "ip"),
        "ports": ("ports", "port"),
        "url": ("url", "target_url", "uri"),
        "wordlist": ("wordlist", "file", "path", "word_list"),
        "command": ("command", "cmd", "script"),
        "exploit": ("exploit", "module"),
        "rhosts": ("RHOSTS", "rhosts", "target"),
    }
    properties = tool_properties(tool)
    arguments: dict[str, Any] = {}
    for logical_name, value in desired.items():
        for alias in aliases.get(logical_name, (logical_name,)):
            if alias in properties:
                arguments[alias] = value
                break
        else:
            arguments[logical_name] = value
    for required_name in tool_required(tool):
        if required_name in arguments:
            continue
        arguments[required_name] = "probe"
    return arguments


def replace_result_tokens(value: str, previous_output: str) -> str:
    return value.replace("RESULT", previous_output.strip())
