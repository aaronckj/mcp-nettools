"""mcp-nettools: Network diagnostics MCP server."""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone

import dns.resolver
import speedtest as _speedtest_lib
from mac_vendor_lookup import AsyncMacLookup
from mcp.server.fastmcp import FastMCP
from wakeonlan import send_magic_packet

mcp = FastMCP("nettools")


@mcp.tool()
def ping(host: str, count: int = 4, timeout: int = 5) -> dict:
    """Ping a host and return reachability and round-trip times."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), host],
            capture_output=True,
            text=True,
            timeout=timeout * count + 5,
        )
        return {
            "host": host,
            "reachable": result.returncode == 0,
            "output": result.stdout,
        }
    except Exception as e:
        return {"error": str(e), "tool": "ping", "host": host}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
