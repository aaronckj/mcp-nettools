"""mcp-nettools: Network diagnostics MCP server."""

from __future__ import annotations

import ssl
import socket
import subprocess
from datetime import datetime, timezone

import dns.resolver
import speedtest as _speedtest_lib
from mac_vendor_lookup import MacLookup
from mcp.server.fastmcp import FastMCP
from wakeonlan import send_magic_packet

mcp = FastMCP("nettools")

_mac = MacLookup()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
