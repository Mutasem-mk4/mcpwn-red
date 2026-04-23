"""Shared attack models and helper utilities."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Iterable, Literal, Sequence

from mcp.types import CallToolResult, TextContent, Tool
from pydantic import BaseModel, Field

AttackStatus = Literal["PASS", "FAIL", "UNKNOWN", "ERROR"]
Severity = Literal["critical", "high", "medium", "low"]

ARG_ALIASES: dict[str, tuple[str, ...]] = {
    "target": ("target", "host", "hostname", "address", "ip", "scan_target", "destination"),
    "ports": ("ports", "port", "p"),
    "url": ("url", "target_url", "endpoint", "uri"),
    "wordlist": ("wordlist", "word_list", "dictionary", "file", "input", "input_file"),
    "path": ("path", "file", "filepath", "filename"),
    "command": ("command", "cmd", "script", "expression"),
    "threads": ("threads", "concurrency", "workers"),
    "module": ("module", "exploit", "scanner"),
    "request_file": ("request_file", "request", "raw_request"),
    "mode": ("mode", "operation", "scan_mode"),
}


class AttackResult(BaseModel):
    id: str
    name: str
    module: Literal["yaml", "output", "container", "scope"]
    status: AttackStatus
    severity: Severity
    evidence: str
    duration_ms: int
    recommendation: str


class ScanReport(BaseModel):
    tool: str = "mcpwn-red"
    version: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    mcpwn_version: str | None = None
    transport: str
    results: list[AttackResult]
    summary: dict[str, int]

    @classmethod
    def from_results(
        cls,
        *,
        version: str,
        transport: str,
        results: list[AttackResult],
        mcpwn_version: str | None,
    ) -> "ScanReport":
        summary = {
            "PASS": sum(1 for item in results if item.status == "PASS"),
            "FAIL": sum(1 for item in results if item.status == "FAIL"),
            "UNKNOWN": sum(1 for item in results if item.status == "UNKNOWN"),
            "ERROR": sum(1 for item in results if item.status == "ERROR"),
        }
        return cls(
            version=version,
            transport=transport,
            results=results,
            summary=summary,
            mcpwn_version=mcpwn_version,
        )


@dataclass(frozen=True, slots=True)
class ToolReference:
    name: str
    description: str
    properties: dict[str, dict[str, Any]]
    required: tuple[str, ...]

    @classmethod
    def from_tool(cls, tool: Tool) -> "ToolReference":
        input_schema = tool.inputSchema if isinstance(tool.inputSchema, dict) else {}
        properties = input_schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}
        required = input_schema.get("required", [])
        required_names = tuple(required) if isinstance(required, list) else ()
        return cls(
            name=tool.name,
            description=tool.description or "",
            properties=properties,
            required=required_names,
        )


class AttackBase(ABC):
    module: Literal["yaml", "output", "container", "scope"]

    @classmethod
    @abstractmethod
    def describe(cls) -> list[dict[str, str]]:
        """Return a static description of all checks exposed by the module."""

    @abstractmethod
    async def run(self) -> list[AttackResult]:
        """Execute the module and return concrete findings."""

    def build_result(
        self,
        *,
        attack_id: str,
        name: str,
        status: AttackStatus,
        severity: Severity,
        evidence: str,
        started_at: float,
        recommendation: str,
    ) -> AttackResult:
        return AttackResult(
            id=attack_id,
            name=name,
            module=self.module,
            status=status,
            severity=severity,
            evidence=truncate_evidence(evidence),
            duration_ms=max(1, int((perf_counter() - started_at) * 1000)),
            recommendation=recommendation,
        )


def truncate_evidence(value: str, limit: int = 1200) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}...(truncated)"


def extract_text_content(result: CallToolResult) -> str:
    chunks: list[str] = []
    for item in result.content:
        if isinstance(item, TextContent):
            chunks.append(item.text)
            continue
        text = getattr(item, "text", None)
        if isinstance(text, str):
            chunks.append(text)
            continue
        chunks.append(str(item))
    return "\n".join(chunks).strip()


def normalize_name(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def find_tool(tools: Sequence[ToolReference], candidates: Iterable[str]) -> ToolReference | None:
    normalized_candidates = {normalize_name(candidate) for candidate in candidates}
    for tool in tools:
        normalized_tool = normalize_name(tool.name)
        if normalized_tool in normalized_candidates:
            return tool
    for tool in tools:
        normalized_tool = normalize_name(tool.name)
        if any(candidate in normalized_tool for candidate in normalized_candidates):
            return tool
    return None


def pick_property_name(tool: ToolReference, logical_name: str) -> str:
    aliases = ARG_ALIASES.get(logical_name, (logical_name,))
    if not tool.properties:
        return aliases[0]
    for alias in aliases:
        if alias in tool.properties:
            return alias
    for property_name in tool.properties:
        normalized_property = normalize_name(property_name)
        if any(normalize_name(alias) == normalized_property for alias in aliases):
            return property_name
    return aliases[0]


def default_value_for_schema(schema: dict[str, Any]) -> Any:
    schema_type = schema.get("type")
    if schema_type == "boolean":
        return False
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1
    if schema_type == "array":
        return []
    if schema_type == "object":
        return {}
    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        return enum_values[0]
    return "probe"


def build_arguments(tool: ToolReference, logical_arguments: dict[str, Any]) -> dict[str, Any]:
    arguments: dict[str, Any] = {}
    for logical_name, value in logical_arguments.items():
        arguments[pick_property_name(tool, logical_name)] = value
    for required_name in tool.required:
        if required_name in arguments:
            continue
        schema = tool.properties.get(required_name, {})
        arguments[required_name] = default_value_for_schema(schema)
    return arguments

