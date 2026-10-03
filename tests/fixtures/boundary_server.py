"""SDK fixture with real file reads inside a disposable test tree; not nmap or Docker."""

import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

fixture_root = Path(sys.argv[1]).resolve()
restricted = sys.argv[2] == "restricted"
workspace = fixture_root / "inside" / "work"
server = FastMCP("Controlled filesystem boundary")


@server.tool()
def nmap(target: str, ports: str = "80") -> str:
    candidate = (workspace / target).resolve()
    if not candidate.is_relative_to(fixture_root):
        return "access denied: outside disposable test tree"
    if restricted and not candidate.is_relative_to(fixture_root / "inside"):
        return "access denied: outside declared workspace"
    if not candidate.is_file():
        return "invalid path"
    return candidate.read_text(encoding="utf-8")


if __name__ == "__main__":
    server.run(transport="stdio")
