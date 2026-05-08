"""mcp-nettools: Network diagnostics MCP server."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
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
_PING_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)%\s+packet loss")
_PING_RTT_RE = re.compile(r"(?:rtt|round-trip)[^\d]*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)")


@mcp.tool()
def ping(host: str, count: int = 4, timeout: int = 5) -> dict:
    """Ping a host and return reachability, packet loss %, and RTT stats. count: 1-30. timeout: 1-60 s per packet."""
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
        out: dict = {
            "host": host,
            "reachable": result.returncode == 0,
            "output": result.stdout,
        }
        loss_m = _PING_LOSS_RE.search(result.stdout)
        if loss_m:
            out["packet_loss_pct"] = float(loss_m.group(1))
        rtt_m = _PING_RTT_RE.search(result.stdout)
        if rtt_m:
            out["rtt_min_ms"] = float(rtt_m.group(1))
            out["rtt_avg_ms"] = float(rtt_m.group(2))
            out["rtt_max_ms"] = float(rtt_m.group(3))
        return out
    except Exception as e:
        return {"error": str(e), "tool": "ping", "host": host}


@mcp.tool()
def dns_lookup(host: str, record_type: str = "A") -> dict:
    """Look up DNS records for a hostname. record_type: A, AAAA, MX, TXT, NS, CNAME, PTR, SOA, SRV."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "dns_lookup"}
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
            "ttl": answers.rrset.ttl if answers.rrset else None,
            "records": [str(r) for r in answers],
        }
    except Exception as e:
        return {"error": str(e), "tool": "dns_lookup", "host": host}


@mcp.tool()
def reverse_dns(ip: str) -> dict:
    """Reverse DNS lookup for an IP address — returns the PTR hostname."""
    if not ip or not ip.strip():
        return {"error": "ip must not be empty", "tool": "reverse_dns"}
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {"ip": ip, "hostname": hostname}
    except socket.herror as e:
        return {"error": str(e), "tool": "reverse_dns", "ip": ip}
    except Exception as e:
        return {"error": str(e), "tool": "reverse_dns", "ip": ip}


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
def port_scan(host: str, ports: str, timeout: int = 3) -> dict:
    """Check multiple TCP ports on a host. ports: comma-separated or ranges (e.g., '22,80,443,8000-8080'). Max 100 ports. timeout: 1-30 s."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "port_scan"}
    if not ports or not ports.strip():
        return {"error": "ports must not be empty", "tool": "port_scan"}
    timeout = min(max(1, timeout), 30)
    port_list: list[int] = []
    for part in ports.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                port_list.extend(range(int(lo), int(hi) + 1))
            except ValueError:
                return {"error": f"Invalid port range: '{part}'", "tool": "port_scan"}
        else:
            try:
                port_list.append(int(part))
            except ValueError:
                return {"error": f"Invalid port number: '{part}'", "tool": "port_scan"}
    if not port_list:
        return {"error": "No valid ports specified", "tool": "port_scan"}
    out_of_range = [p for p in port_list if not 1 <= p <= 65535]
    if out_of_range:
        return {"error": f"Ports out of range 1-65535: {out_of_range[:5]}", "tool": "port_scan"}
    if len(port_list) > 100:
        return {"error": f"Too many ports ({len(port_list)}). Maximum 100 per call.", "tool": "port_scan"}
    results: dict[int, str] = {}
    for port in port_list:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                results[port] = "open"
        except (socket.timeout, ConnectionRefusedError, OSError):
            results[port] = "closed"
    open_ports = sorted(p for p, state in results.items() if state == "open")
    return {
        "result": {
            "host": host,
            "scanned": len(port_list),
            "open_count": len(open_ports),
            "open": open_ports,
            "ports": {str(k): v for k, v in sorted(results.items())},
        }
    }


@mcp.tool()
def traceroute(host: str, max_hops: int = 30, timeout: int = 60) -> dict:
    """Trace the network path to a host. max_hops: 1-64. timeout: 1-300 s."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "traceroute"}
    max_hops = min(max(1, max_hops), 64)
    timeout = min(max(1, timeout), 300)
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
def cert_check(host: str, port: int = 443, timeout: int = 10) -> dict:
    """Check the SSL certificate on a host — expiry, issued date, issuer, SANs, and days remaining. timeout: 1-60 s."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "cert_check"}
    timeout = min(max(1, timeout), 60)
    try:
        ctx = ssl.create_default_context()
        with socket.socket() as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.connect((host, port))
                cert = s.getpeercert()
        fmt = "%b %d %H:%M:%S %Y %Z"
        not_after = datetime.strptime(cert["notAfter"], fmt).replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], fmt).replace(tzinfo=timezone.utc)
        days_remaining = (not_after - datetime.now(timezone.utc)).days
        sans = [v for _type, v in cert.get("subjectAltName", [])]
        return {
            "host": host,
            "port": port,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "not_before": cert["notBefore"],
            "expires": cert["notAfter"],
            "days_remaining": days_remaining,
            "valid": days_remaining > 0,
            "san": sans,
        }
    except Exception as e:
        return {"error": str(e), "tool": "cert_check", "host": host}


@mcp.tool()
def http_check(url: str, method: str = "HEAD", timeout: int = 10) -> dict:
    """Check an HTTP/HTTPS URL: status code, response time in ms, and content type. method: HEAD (default, efficient), GET, or OPTIONS. Use GET if HEAD returns 405."""
    if not url or not url.strip():
        return {"error": "url must not be empty", "tool": "http_check"}
    method = method.upper()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        return {"error": f"Invalid method '{method}'. Use GET, HEAD, or OPTIONS", "tool": "http_check"}
    timeout = min(max(1, timeout), 60)
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed_ms = round((time.monotonic() - start) * 1000, 2)
            return {
                "result": {
                    "status_code": resp.status,
                    "url": resp.url,
                    "elapsed_ms": elapsed_ms,
                    "ok": True,
                    "content_type": resp.headers.get("Content-Type", ""),
                }
            }
    except urllib.error.HTTPError as e:
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        return {
            "result": {
                "status_code": e.code,
                "url": url,
                "elapsed_ms": elapsed_ms,
                "ok": False,
            }
        }
    except Exception as e:
        return {"error": str(e), "tool": "http_check", "detail": type(e).__name__}


@mcp.tool()
def subnet_info(cidr: str) -> dict:
    """Parse a CIDR block: network address, broadcast, host range, host count, and whether it is a private range."""
    if not cidr or not cidr.strip():
        return {"error": "cidr must not be empty", "tool": "subnet_info"}
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        host_list = list(net.hosts())
        return {
            "result": {
                "network": str(net.network_address),
                "broadcast": str(net.broadcast_address),
                "netmask": str(net.netmask),
                "prefix_length": net.prefixlen,
                "first_host": str(host_list[0]) if host_list else None,
                "last_host": str(host_list[-1]) if host_list else None,
                "host_count": len(host_list),
                "total_addresses": net.num_addresses,
                "is_private": net.is_private,
            }
        }
    except ValueError as e:
        return {"error": str(e), "tool": "subnet_info"}


@mcp.tool()
def arp_table(interface: str = "") -> dict:
    """Show ARP/neighbor table entries (IP-to-MAC mappings). interface: optional filter by network interface name."""
    try:
        cmd = ["ip", "neigh", "show"]
        if interface and interface.strip():
            cmd += ["dev", interface.strip()]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {
            "result": {
                "output": result.stdout,
                "returncode": result.returncode,
            }
        }
    except FileNotFoundError:
        try:
            cmd2 = ["arp", "-an"]
            result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=10)
            return {"result": {"output": result2.stdout, "returncode": result2.returncode}}
        except Exception as e2:
            return {"error": str(e2), "tool": "arp_table", "detail": type(e2).__name__}
    except Exception as e:
        return {"error": str(e), "tool": "arp_table", "detail": type(e).__name__}


@mcp.tool()
def wake_on_lan(mac: str, broadcast: str = "255.255.255.255") -> dict:
    """Send a Wake-on-LAN magic packet to a MAC address."""
    if not _MAC_RE.match(mac):
        return {
            "error": f"Invalid MAC address '{mac}'. Expected XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX",
            "tool": "wake_on_lan",
        }
    try:
        ipaddress.IPv4Address(broadcast)
    except ValueError:
        return {"error": f"Invalid broadcast address '{broadcast}': must be a valid IPv4 address", "tool": "wake_on_lan"}
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
            _mac_lookup_instance = instance
        vendor = await _mac_lookup_instance.lookup(mac)
        return {"mac": mac, "vendor": vendor}
    except Exception as e:
        return {"error": str(e), "tool": "mac_lookup", "mac": mac}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
