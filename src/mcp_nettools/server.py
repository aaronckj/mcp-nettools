"""mcp-nettools: Network diagnostics MCP server."""

from __future__ import annotations

import socket
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


@mcp.tool()
def dns_lookup(host: str, record_type: str = "A") -> dict:
    """Look up DNS records for a hostname. record_type: A, AAAA, MX, TXT, NS, CNAME."""
    try:
        answers = dns.resolver.resolve(host, record_type)
        return {
            "host": host,
            "record_type": record_type,
            "records": [str(r) for r in answers],
        }
    except Exception as e:
        return {"error": str(e), "tool": "dns_lookup", "host": host}


@mcp.tool()
def port_check(host: str, port: int, timeout: int = 5) -> dict:
    """Check if a TCP port is open on a host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
        return {"host": host, "port": port, "open": result == 0}
    except Exception as e:
        return {"error": str(e), "tool": "port_check", "host": host, "port": port}


@mcp.tool()
def traceroute(host: str, max_hops: int = 30, timeout: int = 60) -> dict:
    """Trace the network path to a host."""
    try:
        result = subprocess.run(
            ["traceroute", "-m", str(max_hops), host],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "host": host,
            "output": result.stdout,
            "returncode": result.returncode,
        }
    except Exception as e:
        return {"error": str(e), "tool": "traceroute", "host": host}


@mcp.tool()
def wake_on_lan(mac: str, broadcast: str = "255.255.255.255") -> dict:
    """Send a Wake-on-LAN magic packet to a MAC address."""
    try:
        send_magic_packet(mac, ip_address=broadcast)
        return {"mac": mac, "broadcast": broadcast, "sent": True}
    except Exception as e:
        return {"error": str(e), "tool": "wake_on_lan", "mac": mac}


@mcp.tool()
def speedtest() -> dict:
    """Run a network speed test using the nearest server."""
    try:
        st = _speedtest_lib.Speedtest()
        st.get_best_server()
        return {
            "download_mbps": round(st.download() / 1_000_000, 2),
            "upload_mbps": round(st.upload() / 1_000_000, 2),
            "ping_ms": st.results.ping,
            "server": st.results.server.get("name"),
        }
    except Exception as e:
        return {"error": str(e), "tool": "speedtest"}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
