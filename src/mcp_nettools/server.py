"""mcp-nettools: Network diagnostics MCP server."""

from __future__ import annotations

import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone

import dns.resolver
import speedtest as _speedtest_lib
from mac_vendor_lookup import AsyncMacLookup
from mcp.server.fastmcp import FastMCP
from wakeonlan import send_magic_packet

mcp = FastMCP("nettools")

_VALID_RECORD_TYPES = {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "PTR", "SOA", "SRV"}
_mac_lookup_instance: AsyncMacLookup | None = None
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")


@mcp.tool()
def ping(host: str, count: int = 4, timeout: int = 5) -> dict:
    """Ping a host and return reachability and round-trip times. count: 1-30. timeout: 1-60 s per packet."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "ping"}
    count = min(max(1, count), 30)
    timeout = min(max(1, timeout), 60)
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
    """Look up DNS records for a hostname. record_type: A, AAAA, MX, TXT, NS, CNAME, PTR, SOA, SRV."""
    record_type = record_type.upper()
    if record_type not in _VALID_RECORD_TYPES:
        return {
            "error": f"Invalid record type '{record_type}'. Valid: {', '.join(sorted(_VALID_RECORD_TYPES))}",
            "tool": "dns_lookup",
        }
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10.0
        answers = resolver.resolve(host, record_type)
        return {
            "host": host,
            "record_type": record_type,
            "records": [str(r) for r in answers],
        }
    except Exception as e:
        return {"error": str(e), "tool": "dns_lookup", "host": host}


@mcp.tool()
def port_check(host: str, port: int, timeout: int = 5) -> dict:
    """Check if a TCP port is open on a host. port: 1-65535. timeout: 1-300 s. Supports IPv4 and IPv6."""
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1–65535", "tool": "port_check"}
    timeout = min(max(1, timeout), 300)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return {"host": host, "port": port, "open": True}
    except OSError:
        return {"host": host, "port": port, "open": False}
    except Exception as e:
        return {"error": str(e), "tool": "port_check", "host": host, "port": port}


@mcp.tool()
def traceroute(host: str, max_hops: int = 30, timeout: int = 60) -> dict:
    """Trace the network path to a host. max_hops: 1-64."""
    max_hops = min(max(1, max_hops), 64)
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
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except Exception as e:
        return {"error": str(e), "tool": "traceroute", "host": host}


@mcp.tool()
def cert_check(host: str, port: int = 443) -> dict:
    """Check the SSL certificate on a host — expiry, issuer, SANs, and days remaining."""
    try:
        ctx = ssl.create_default_context()
        with socket.socket() as raw:
            raw.settimeout(10)
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.connect((host, port))
                cert = s.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_remaining = (not_after - datetime.now(timezone.utc)).days
        sans = [v for _type, v in cert.get("subjectAltName", [])]
        return {
            "host": host,
            "port": port,
            "subject": dict(x[0] for x in cert["subject"]),
            "issuer": dict(x[0] for x in cert["issuer"]),
            "expires": cert["notAfter"],
            "days_remaining": days_remaining,
            "valid": days_remaining > 0,
            "san": sans,
        }
    except Exception as e:
        return {"error": str(e), "tool": "cert_check", "host": host}


@mcp.tool()
def wake_on_lan(mac: str, broadcast: str = "255.255.255.255") -> dict:
    """Send a Wake-on-LAN magic packet to a MAC address."""
    if not _MAC_RE.match(mac):
        return {
            "error": f"Invalid MAC address '{mac}'. Expected XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX",
            "tool": "wake_on_lan",
        }
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


@mcp.tool()
def whois(host: str) -> dict:
    """Look up WHOIS registration data for a domain or IP address."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "whois"}
    try:
        result = subprocess.run(
            ["whois", host],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "host": host,
            "output": result.stdout,
            "returncode": result.returncode,
        }
    except FileNotFoundError:
        return {"error": "whois command not found; install whois package", "tool": "whois", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "whois", "host": host}


@mcp.tool()
async def mac_lookup(mac: str) -> dict:
    """Look up the vendor/manufacturer for a MAC address (OUI database)."""
    global _mac_lookup_instance
    try:
        if _mac_lookup_instance is None:
            instance = AsyncMacLookup()
            await instance.load_vendors()
            _mac_lookup_instance = instance  # only assigned after successful load
        vendor = await _mac_lookup_instance.lookup(mac)
        return {"mac": mac, "vendor": vendor}
    except Exception as e:
        return {"error": str(e), "tool": "mac_lookup", "mac": mac}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
