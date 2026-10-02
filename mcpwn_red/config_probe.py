from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from mcpwn_red.mcp_client import MCPClient, MCPClientError


@dataclass(frozen=True)
class ConfigurationResult:
    tools: list[dict[str, Any]]
    error: str | None = None
    rejected: bool = False


class MCPwnConfigProbe:
    def __init__(self, command: str, timeout: int) -> None:
        self.command = command
        self.timeout = timeout

    async def inspect(self, configuration: str) -> ConfigurationResult:
        executable = shutil.which(self.command)
        if executable is None:
            return ConfigurationResult([], f"MCPwn executable not found: {self.command}")
        try:
            with TemporaryDirectory(prefix="mcpwn-red-") as directory:
                isolated = Path(directory)
                command = isolated / Path(executable).name
                shutil.copy2(executable, command)
                (isolated / "mcpwn.yaml").write_text(configuration, encoding="utf-8")
                return await self._list_tools(command, isolated / "stderr.log")
        except OSError as exc:
            return ConfigurationResult([], f"Isolated configuration setup failed: {exc}")

    async def _list_tools(self, command: Path, stderr_path: Path) -> ConfigurationResult:
        with stderr_path.open("w+", encoding="utf-8") as stderr:
            try:
                async with MCPClient(
                    command=str(command), timeout=self.timeout, errlog=stderr
                ) as client:
                    return ConfigurationResult(await client.list_tools())
            except MCPClientError as exc:
                stderr.seek(0)
                diagnostics = stderr.read()
                rejected = "Configuration load error" in diagnostics and any(
                    marker in diagnostics
                    for marker in ("failed to parse configuration", "invalid configuration")
                )
                return ConfigurationResult([], f"{exc}\n{diagnostics}", rejected)
