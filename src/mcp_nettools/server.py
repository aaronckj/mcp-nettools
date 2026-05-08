"""mcp-nettools: Network diagnostics MCP server."""

from __future__ import annotations

import concurrent.futures
import hashlib
import ipaddress
import json
import re
import smtplib
import socket
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.parse
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
    host = host.strip()
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
        if result.stderr:
            out["stderr"] = result.stderr
        loss_m = _PING_LOSS_RE.search(result.stdout)
        if loss_m:
            out["packet_loss_pct"] = float(loss_m.group(1))
        rtt_m = _PING_RTT_RE.search(result.stdout)
        if rtt_m:
            out["rtt_min_ms"] = float(rtt_m.group(1))
            out["rtt_avg_ms"] = float(rtt_m.group(2))
            out["rtt_max_ms"] = float(rtt_m.group(3))
        return {"result": out}
    except Exception as e:
        return {"error": str(e), "tool": "ping", "host": host}


@mcp.tool()
def dns_lookup(host: str, record_type: str = "A", nameserver: str = "") -> dict:
    """Look up DNS records for a hostname. record_type: A, AAAA, MX, TXT, NS, CNAME, PTR, SOA, SRV. nameserver: optional custom resolver IP (e.g., '8.8.8.8' for Google DNS, '1.1.1.1' for Cloudflare)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "dns_lookup"}
    host = host.strip()
    record_type = record_type.strip().upper()
    if record_type not in _VALID_RECORD_TYPES:
        return {
            "error": f"Invalid record type '{record_type}'. Valid: {', '.join(sorted(_VALID_RECORD_TYPES))}",
            "tool": "dns_lookup",
        }
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10.0
        if nameserver and nameserver.strip():
            try:
                ipaddress.ip_address(nameserver.strip())
            except ValueError:
                return {"error": f"Invalid nameserver IP: '{nameserver}'", "tool": "dns_lookup"}
            resolver.nameservers = [nameserver.strip()]
        answers = resolver.resolve(host, record_type)
        return {
            "result": {
                "host": host,
                "record_type": record_type,
                "nameserver": nameserver.strip() if nameserver and nameserver.strip() else None,
                "ttl": answers.rrset.ttl if answers.rrset else None,
                "records": [str(r) for r in answers],
            }
        }
    except Exception as e:
        return {"error": str(e), "tool": "dns_lookup", "host": host}


@mcp.tool()
def reverse_dns(ip: str) -> dict:
    """Reverse DNS lookup for an IP address — returns the PTR hostname."""
    if not ip or not ip.strip():
        return {"error": "ip must not be empty", "tool": "reverse_dns"}
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": f"Invalid IP address: '{ip}'. reverse_dns requires an IP, not a hostname. Use dns_lookup for forward lookups.", "tool": "reverse_dns"}
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {"result": {"ip": ip, "hostname": hostname}}
    except socket.herror as e:
        return {"error": str(e), "tool": "reverse_dns", "ip": ip}
    except Exception as e:
        return {"error": str(e), "tool": "reverse_dns", "ip": ip}



@mcp.tool()
def reverse_dns_bulk(ips: str) -> dict:
    """Reverse DNS lookup for multiple IP addresses at once. ips: comma-separated IPv4 or IPv6 addresses (max 50). Returns PTR hostname for each IP, or an error if lookup fails."""
    if not ips or not ips.strip():
        return {"error": "ips must not be empty", "tool": "reverse_dns_bulk"}
    ips = ips.strip()
    ip_list = [ip.strip() for ip in ips.split(",") if ip.strip()]
    if not ip_list:
        return {"error": "No valid IPs found in input", "tool": "reverse_dns_bulk"}
    if len(ip_list) > 50:
        return {"error": f"Too many IPs ({len(ip_list)}). Maximum 50 per call.", "tool": "reverse_dns_bulk"}
    invalid = []
    for ip in ip_list:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            invalid.append(ip)
    if invalid:
        return {"error": f"Invalid IP addresses: {invalid[:5]}", "tool": "reverse_dns_bulk"}

    def _rdns(ip: str) -> tuple[str, str | None, str | None]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return ip, hostname, None
        except socket.herror as e:
            return ip, None, str(e)
        except Exception as e:
            return ip, None, str(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ip_list), 20)) as pool:
        raw = list(pool.map(_rdns, ip_list))

    results = {ip: {"hostname": h, "error": err} if err else {"hostname": h} for ip, h, err in raw}
    resolved = sum(1 for r in results.values() if "hostname" in r and r["hostname"])
    return {"result": {"resolved": resolved, "total": len(ip_list), "ips": results}}


def _probe_port(host: str, port: int, timeout: float) -> bool:
    """Return True if TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


@mcp.tool()
def port_check(host: str, port: int, timeout: int = 5) -> dict:
    """Check if a TCP port is open on a host. port: 1-65535. timeout: 1-300 s. Supports IPv4 and IPv6."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "port_check"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1–65535", "tool": "port_check"}
    timeout = min(max(1, timeout), 300)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return {"result": {"host": host, "port": port, "open": True}}
    except OSError:
        return {"result": {"host": host, "port": port, "open": False}}
    except Exception as e:
        return {"error": str(e), "tool": "port_check", "host": host, "port": port}


@mcp.tool()
def port_scan(host: str, ports: str, timeout: int = 3) -> dict:
    """Check multiple TCP ports on a host. ports: comma-separated or ranges (e.g., '22,80,443,8000-8080'). Max 500 ports. timeout: 1-30 s."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "port_scan"}
    host = host.strip()
    if not ports or not ports.strip():
        return {"error": "ports must not be empty", "tool": "port_scan"}
    ports = ports.strip()
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
    port_list = sorted(set(port_list))
    if len(port_list) > 500:
        return {"error": f"Too many ports ({len(port_list)}). Maximum 500 per call.", "tool": "port_scan"}
    workers = min(len(port_list), 100)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_port = {pool.submit(_probe_port, host, p, timeout): p for p in port_list}
        results = {
            future_to_port[f]: "open" if f.result() else "closed"
            for f in concurrent.futures.as_completed(future_to_port)
        }
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
def traceroute(host: str, max_hops: int = 30, timeout: int = 60, wait: int = 2) -> dict:
    """Trace the network path to a host. max_hops: 1-64. timeout: overall timeout in seconds. wait: per-hop probe wait time in seconds (1-10, default 2; increase to 5-10 for high-latency satellite/VPN links)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "traceroute"}
    host = host.strip()
    max_hops = min(max(1, max_hops), 64)
    timeout = min(max(1, timeout), 300)
    wait = min(max(1, wait), 10)
    try:
        result = subprocess.run(
            ["traceroute", "-m", str(max_hops), "-w", str(wait), host],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "result": {
                "host": host,
                "output": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
        }
    except Exception as e:
        return {"error": str(e), "tool": "traceroute", "host": host}


@mcp.tool()
def cert_check(host: str, port: int = 443, timeout: int = 10) -> dict:
    """Check the SSL certificate on a host — expiry, issued date, issuer, SANs, and days remaining. timeout: 1-60 s."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "cert_check"}
    host = host.strip()
    # Strip port suffix if present (e.g. "example.com:443" → "example.com") for correct SNI
    if ":" in host and not host.startswith("["):
        maybe_host, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit():
            host = maybe_host
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "cert_check"}
    timeout = min(max(1, timeout), 60)
    def _parse_cert(cert: dict, cert_der: bytes, verified: bool) -> dict:
        fmt = "%b %d %H:%M:%S %Y %Z"
        not_after = datetime.strptime(cert["notAfter"], fmt).replace(tzinfo=timezone.utc)
        days_remaining = (not_after - datetime.now(timezone.utc)).days
        sans = [v for _type, v in cert.get("subjectAltName", [])]
        fp = hashlib.sha256(cert_der).hexdigest() if cert_der else None
        return {
            "host": host,
            "port": port,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "serial_number": cert.get("serialNumber", ""),
            "not_before": cert["notBefore"],
            "expires": cert["notAfter"],
            "days_remaining": days_remaining,
            "valid": days_remaining > 0,
            "verified": verified,
            "san": sans,
            "sha256_fingerprint": fp,
        }

    try:
        ctx = ssl.create_default_context()
        with socket.socket() as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.connect((host, port))
                cert = s.getpeercert()
                cert_der = s.getpeercert(binary_form=True)
        return {"result": _parse_cert(cert, cert_der, verified=True)}
    except ssl.SSLCertVerificationError as verify_err:
        # Cert exists but chain/expiry invalid — retry without verification to get cert details
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.socket() as raw2:
                raw2.settimeout(timeout)
                with ctx2.wrap_socket(raw2, server_hostname=host) as s2:
                    s2.connect((host, port))
                    cert2 = s2.getpeercert()
                    cert_der2 = s2.getpeercert(binary_form=True)
            if cert2:
                result = _parse_cert(cert2, cert_der2, verified=False)
                result["ssl_error"] = str(verify_err)
                return {"result": result}
            # CERT_NONE returns empty dict — return fingerprint only
            fp = hashlib.sha256(cert_der2).hexdigest() if cert_der2 else None
            return {
                "result": {
                    "host": host, "port": port, "verified": False,
                    "ssl_error": str(verify_err), "sha256_fingerprint": fp,
                }
            }
        except Exception:
            pass
        return {"error": str(verify_err), "tool": "cert_check", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "cert_check", "host": host}


@mcp.tool()
def http_check(url: str, method: str = "HEAD", timeout: int = 10, expected_status: int = 0, contains: str = "", headers: str = "") -> dict:
    """Check an HTTP/HTTPS URL: status code, response time, content type, and server header. method: HEAD (default, efficient), GET, or OPTIONS. Use GET if HEAD returns 405. expected_status: if non-zero, also checks response matches this code. contains: optional string that must appear in response body (GET only). headers: optional extra request headers as 'Name: Value' pairs separated by newlines or semicolons (e.g. 'Authorization: Bearer token123;X-Custom: value')."""
    if not url or not url.strip():
        return {"error": "url must not be empty", "tool": "http_check"}
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    method = method.upper()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        return {"error": f"Invalid method '{method}'. Use GET, HEAD, or OPTIONS", "tool": "http_check"}
    timeout = min(max(1, timeout), 60)
    start = time.monotonic()
    extra_headers: dict[str, str] = {}
    if headers and headers.strip():
        for raw in re.split(r"[;\n]", headers):
            raw = raw.strip()
            if not raw:
                continue
            if ":" not in raw:
                return {"error": f"Invalid header '{raw}': must be 'Name: Value'", "tool": "http_check"}
            hname, _, hval = raw.partition(":")
            extra_headers[hname.strip()] = hval.strip()
    try:
        req = urllib.request.Request(url, method=method, headers=extra_headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed_ms = round((time.monotonic() - start) * 1000, 2)
            body = resp.read().decode("utf-8", errors="replace") if method == "GET" else ""
            result: dict = {
                "status_code": resp.status,
                "url": resp.url,
                "elapsed_ms": elapsed_ms,
                "ok": True,
                "content_type": resp.headers.get("Content-Type", ""),
                "server": resp.headers.get("Server", ""),
                "content_length": resp.headers.get("Content-Length", ""),
            }
            if expected_status:
                result["status_ok"] = resp.status == expected_status
            if contains and method == "GET":
                result["contains_ok"] = contains in body
            elif contains and method != "GET":
                result["contains_note"] = f"contains check skipped: requires method=GET, got {method}"
            return {"result": result}
    except urllib.error.HTTPError as e:
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        result = {
            "status_code": e.code,
            "url": url,
            "elapsed_ms": elapsed_ms,
            "ok": False,
            "content_type": e.headers.get("Content-Type", "") if e.headers else "",
            "server": e.headers.get("Server", "") if e.headers else "",
        }
        if expected_status:
            result["status_ok"] = e.code == expected_status
        return {"result": result}
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "Name or service not known" in reason or "nodename nor servname" in reason:
            detail = "DNS resolution failed"
        elif "Connection refused" in reason:
            detail = "connection refused"
        elif "timed out" in reason.lower():
            detail = "connection timed out"
        else:
            detail = reason
        return {"error": detail, "tool": "http_check", "url": url}
    except Exception as e:
        return {"error": str(e), "tool": "http_check", "detail": type(e).__name__}


@mcp.tool()
def subnet_info(cidr: str) -> dict:
    """Parse an IPv4 or IPv6 CIDR block: network address, host range, host count, and whether it is a private range. IPv4 also returns broadcast and netmask."""
    if not cidr or not cidr.strip():
        return {"error": "cidr must not be empty", "tool": "subnet_info"}
    cidr = cidr.strip()
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return {"error": str(e), "tool": "subnet_info"}

    if isinstance(net, ipaddress.IPv4Network):
        # Don't materialize host list for large networks — /8 = 16M entries, /1 = 2.1B
        if net.prefixlen >= 31:
            # /31 (point-to-point) and /32 (host) have no conventional "usable hosts"
            first_host = str(net.network_address)
            last_host = str(net.broadcast_address)
            host_count = net.num_addresses
        else:
            first_host = str(net.network_address + 1)
            last_host = str(net.broadcast_address - 1)
            host_count = net.num_addresses - 2
        return {
            "result": {
                "version": 4,
                "network": str(net.network_address),
                "broadcast": str(net.broadcast_address),
                "netmask": str(net.netmask),
                "prefix_length": net.prefixlen,
                "first_host": first_host,
                "last_host": last_host,
                "host_count": host_count,
                "total_addresses": net.num_addresses,
                "is_private": net.is_private,
                "is_loopback": net.is_loopback,
                "is_link_local": net.is_link_local,
                "is_multicast": net.is_multicast,
                "is_global": net.is_global,
            }
        }
    else:
        return {
            "result": {
                "version": 6,
                "network": str(net.network_address),
                "prefix_length": net.prefixlen,
                "total_addresses": net.num_addresses,
                "is_private": net.is_private,
                "is_link_local": net.is_link_local,
                "is_global": net.is_global,
            }
        }


@mcp.tool()
def geolocation(ip: str) -> dict:
    """Look up geolocation data for a public IP address: country, region, city, ISP, and coordinates. Uses ipinfo.io (no API key required for basic lookups)."""
    if not ip or not ip.strip():
        return {"error": "ip must not be empty", "tool": "geolocation"}
    ip = ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"error": f"Invalid IP address: '{ip}'", "tool": "geolocation"}
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return {"error": f"'{ip}' is a private/reserved address; geolocation is only available for public IPs", "tool": "geolocation"}
    try:
        req = urllib.request.Request(
            f"https://ipinfo.io/{ip}/json",
            headers={"Accept": "application/json", "User-Agent": "mcp-nettools/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return {"result": data}
    except Exception as e:
        return {"error": str(e), "tool": "geolocation", "detail": type(e).__name__}


@mcp.tool()
def get_public_ip() -> dict:
    """Return the public IP address of the machine running this MCP server, plus basic geolocation (country, region, city, ISP). Useful for verifying internet connectivity, checking what IP external services see, and confirming NAT is working as expected."""
    try:
        req = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"Accept": "application/json", "User-Agent": "mcp-nettools/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return {"result": data}
    except Exception as e:
        return {"error": str(e), "tool": "get_public_ip", "detail": type(e).__name__}


@mcp.tool()
def arp_table(interface: str = "") -> dict:
    """Show ARP/neighbor table entries (IP-to-MAC mappings) as structured records. interface: optional filter by network interface name. Returns list with ip, mac, interface, and state fields."""
    _NEIGH_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "NOARP", "PERMANENT", "INCOMPLETE"}

    def _parse_ip_neigh(output: str) -> list[dict]:
        entries = []
        for line in output.strip().splitlines():
            parts = line.split()
            if not parts:
                continue
            entry: dict = {"ip": parts[0], "mac": None, "interface": None, "state": None}
            try:
                entry["interface"] = parts[parts.index("dev") + 1]
            except (ValueError, IndexError):
                pass
            try:
                entry["mac"] = parts[parts.index("lladdr") + 1]
            except (ValueError, IndexError):
                pass
            for p in reversed(parts):
                if p.upper() in _NEIGH_STATES:
                    entry["state"] = p.upper()
                    break
            entries.append(entry)
        return entries

    try:
        cmd = ["ip", "neigh", "show"]
        if interface and interface.strip():
            cmd += ["dev", interface.strip()]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        entries = _parse_ip_neigh(result.stdout)
        return {"result": {"entries": entries, "count": len(entries)}}
    except FileNotFoundError:
        try:
            cmd2 = ["arp", "-an"]
            result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=10)
            return {"result": {"raw_output": result2.stdout}}
        except Exception as e2:
            return {"error": str(e2), "tool": "arp_table", "detail": type(e2).__name__}
    except Exception as e:
        return {"error": str(e), "tool": "arp_table", "detail": type(e).__name__}


@mcp.tool()
def wake_on_lan(mac: str, broadcast: str = "255.255.255.255") -> dict:
    """Send a Wake-on-LAN magic packet to a MAC address."""
    if not mac or not mac.strip():
        return {"error": "mac must not be empty", "tool": "wake_on_lan"}
    mac = mac.strip()
    if not _MAC_RE.match(mac):
        return {
            "error": f"Invalid MAC address '{mac}'. Expected XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX",
            "tool": "wake_on_lan",
        }
    broadcast = broadcast.strip()
    try:
        ipaddress.IPv4Address(broadcast)
    except ValueError:
        return {"error": f"Invalid broadcast address '{broadcast}': must be a valid IPv4 address", "tool": "wake_on_lan"}
    try:
        send_magic_packet(mac, ip_address=broadcast)
        return {"result": {"mac": mac, "broadcast": broadcast, "sent": True}}
    except Exception as e:
        return {"error": str(e), "tool": "wake_on_lan", "mac": mac}


@mcp.tool()
def speedtest() -> dict:
    """Run a network speed test using the nearest server."""
    try:
        st = _speedtest_lib.Speedtest()
        st.get_best_server()
        results = st.results
        return {
            "result": {
                "download_mbps": round(st.download() / 1_000_000, 2),
                "upload_mbps": round(st.upload() / 1_000_000, 2),
                "ping_ms": results.ping,
                "server": (results.server or {}).get("name"),
            }
        }
    except Exception as e:
        return {"error": str(e), "tool": "speedtest"}


@mcp.tool()
def whois(host: str) -> dict:
    """Look up WHOIS registration data for a domain or IP address. Output is truncated at 8000 characters."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "whois"}
    host = host.strip()
    _MAX = 8000
    try:
        result = subprocess.run(
            ["whois", host],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout
        truncated = len(output) > _MAX
        return {
            "result": {
                "host": host,
                "output": output[:_MAX],
                "returncode": result.returncode,
                **({"truncated": True, "original_length": len(output)} if truncated else {}),
            }
        }
    except FileNotFoundError:
        return {"error": "whois command not found; install whois package", "tool": "whois", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "whois", "host": host}


@mcp.tool()
async def mac_lookup(mac: str) -> dict:
    """Look up the vendor/manufacturer for a MAC address (OUI database)."""
    global _mac_lookup_instance
    if not mac or not mac.strip():
        return {"error": "mac must not be empty", "tool": "mac_lookup"}
    mac = mac.strip()
    if not _MAC_RE.match(mac):
        return {
            "error": f"Invalid MAC address '{mac}'. Expected XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX",
            "tool": "mac_lookup",
        }
    try:
        if _mac_lookup_instance is None:
            instance = AsyncMacLookup()
            await instance.load_vendors()
            _mac_lookup_instance = instance
        vendor = await _mac_lookup_instance.lookup(mac)
        return {"result": {"mac": mac, "vendor": vendor}}
    except Exception as e:
        return {"error": str(e), "tool": "mac_lookup", "mac": mac}



@mcp.tool()
def smtp_check(host: str, port: int = 25, timeout: int = 10, check_starttls: bool = True) -> dict:
    """Check an SMTP server: connectivity, banner, advertised capabilities, and STARTTLS support. port: 25 (SMTP), 465 (SMTPS/SSL), 587 (submission). check_starttls: attempt STARTTLS upgrade on port 25/587."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "smtp_check"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "smtp_check"}
    timeout = min(max(1, timeout), 60)
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                caps = list(smtp.esmtp_features.keys())
                return {"result": {"host": host, "port": port, "reachable": True, "tls": "direct_ssl", "capabilities": caps}}
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                caps = list(smtp.esmtp_features.keys())
                starttls_advertised = smtp.has_extn("STARTTLS")
                tls_status = "none"
                if check_starttls and starttls_advertised:
                    try:
                        smtp.starttls()
                        smtp.ehlo()
                        tls_status = "upgraded"
                        caps = list(smtp.esmtp_features.keys())
                    except Exception as tls_e:
                        tls_status = f"failed: {tls_e}"
                return {
                    "result": {
                        "host": host,
                        "port": port,
                        "reachable": True,
                        "starttls_advertised": starttls_advertised,
                        "tls": tls_status,
                        "capabilities": caps,
                    }
                }
    except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, ConnectionRefusedError, TimeoutError, socket.timeout) as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e)}}
    except Exception as e:
        return {"error": str(e), "tool": "smtp_check", "detail": type(e).__name__}


@mcp.tool()
def ntp_check(host: str, port: int = 123, timeout: int = 5) -> dict:
    """Check an NTP server: reachability and clock offset relative to local system time. Uses NTPv3 client packet over UDP. offset_seconds > 0 means server is ahead of local clock."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "ntp_check"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "ntp_check"}
    timeout = min(max(1, timeout), 30)
    # NTPv3 client request: LI=0, VN=3, Mode=3
    NTP_PACKET = b"\x1b" + b"\x00" * 47
    NTP_DELTA = 2208988800  # seconds between NTP epoch (1900) and Unix epoch (1970)
    try:
        addrinfos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        if not addrinfos:
            return {"result": {"host": host, "port": port, "reachable": False, "reason": "DNS resolution failed"}}
        af, _, _, _, addr = addrinfos[0]
        with socket.socket(af, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            send_time = time.time()
            s.sendto(NTP_PACKET, addr)
            data, _ = s.recvfrom(1024)
        recv_time = time.time()
        if len(data) < 48:
            return {"error": "NTP response too short — server may not speak NTP", "tool": "ntp_check", "host": host}
        # Transmit timestamp: bytes 40-47, integer part in first 4 bytes
        tx_int = struct.unpack("!I", data[40:44])[0]
        tx_frac = struct.unpack("!I", data[44:48])[0]
        server_time = (tx_int - NTP_DELTA) + tx_frac / 2**32
        local_time = (send_time + recv_time) / 2
        offset = server_time - local_time
        rtt = recv_time - send_time
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "offset_seconds": round(offset, 6),
                "rtt_seconds": round(rtt, 6),
                "server_time_utc": datetime.fromtimestamp(server_time, tz=timezone.utc).isoformat(),
            }
        }
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "error": "connection timed out"}}
    except Exception as e:
        return {"error": str(e), "tool": "ntp_check", "detail": type(e).__name__}


@mcp.tool()
def dns_bulk_lookup(hosts: str, record_type: str = "A", nameserver: str = "") -> dict:
    """Look up DNS records for multiple hostnames in one call. hosts: comma-separated list (e.g., 'google.com,github.com,cloudflare.com'). Max 20 hosts. record_type: A, AAAA, MX, TXT, etc. nameserver: optional custom resolver IP."""
    if not hosts or not hosts.strip():
        return {"error": "hosts must not be empty", "tool": "dns_bulk_lookup"}
    hosts = hosts.strip()
    host_list = [h.strip() for h in hosts.split(",") if h.strip()]
    if not host_list:
        return {"error": "No valid hosts specified", "tool": "dns_bulk_lookup"}
    if len(host_list) > 20:
        return {"error": f"Too many hosts ({len(host_list)}). Maximum 20 per call.", "tool": "dns_bulk_lookup"}
    record_type = record_type.strip().upper()
    if record_type not in _VALID_RECORD_TYPES:
        return {
            "error": f"Invalid record type '{record_type}'. Valid: {', '.join(sorted(_VALID_RECORD_TYPES))}",
            "tool": "dns_bulk_lookup",
        }
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10.0
    if nameserver and nameserver.strip():
        try:
            ipaddress.ip_address(nameserver.strip())
        except ValueError:
            return {"error": f"Invalid nameserver IP: '{nameserver}'", "tool": "dns_bulk_lookup"}
        resolver.nameservers = [nameserver.strip()]

    def _lookup_one(h: str) -> tuple[str, dict]:
        try:
            answers = resolver.resolve(h, record_type)
            return h, {"records": [str(r) for r in answers], "ttl": answers.rrset.ttl if answers.rrset else None}
        except dns.resolver.NXDOMAIN:
            return h, {"error": "NXDOMAIN — domain does not exist"}
        except dns.resolver.NoAnswer:
            return h, {"error": f"No {record_type} records found"}
        except Exception as e:
            return h, {"error": str(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(host_list), 20)) as pool:
        results = dict(pool.map(_lookup_one, host_list))

    return {"result": {"record_type": record_type, "nameserver": nameserver.strip() if nameserver and nameserver.strip() else None, "hosts": results}}


_COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 8080: "http-alt", 8443: "https-alt",
}


@mcp.tool()
def ftp_check(host: str, port: int = 21, timeout: int = 10) -> dict:
    """Connect to an FTP server and read its banner. Also tests whether anonymous login is accepted. Useful for verifying FTP service availability."""
    import ftplib
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "ftp_check"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "ftp_check"}
    timeout = min(max(1, timeout), 30)
    try:
        with ftplib.FTP() as ftp:
            ftp.connect(host, port, timeout)
            welcome = ftp.getwelcome()
            anon_ok = False
            try:
                ftp.login()
                anon_ok = True
            except ftplib.all_errors:
                pass
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "welcome": welcome,
                "anonymous_login": anon_ok,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "ftp_check", "host": host, "detail": type(e).__name__}


@mcp.tool()
def tcp_banner(host: str, port: int, timeout: int = 5) -> dict:
    """Connect to any TCP port and read the initial server banner. Useful for identifying unknown services or verifying custom TCP servers. Returns raw banner text."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "tcp_banner"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": "port must be between 1 and 65535", "tool": "tcp_banner"}
    timeout = min(max(1, timeout), 30)
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                raw = sock.recv(4096)
                banner = raw.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                banner = ""
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        return {
            "result": {
                "host": host,
                "port": port,
                "open": True,
                "banner": banner,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "open": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "open": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "tcp_banner", "host": host, "detail": type(e).__name__}


@mcp.tool()
def scan_common_ports(host: str, timeout: int = 2) -> dict:
    """Scan 17 commonly used ports on a host and report which are open (FTP, SSH, HTTP, HTTPS, SMTP, DNS, MySQL, PostgreSQL, RDP, SMB, etc.). Faster alternative to running port_check 17 times."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "scan_common_ports"}
    host = host.strip()
    timeout = min(max(1, timeout), 10)
    open_ports = []
    closed_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(_COMMON_PORTS)) as pool:
        future_to_info = {pool.submit(_probe_port, host, p, timeout): (p, s) for p, s in _COMMON_PORTS.items()}
        for f in concurrent.futures.as_completed(future_to_info):
            port, service = future_to_info[f]
            (open_ports if f.result() else closed_ports).append({"port": port, "service": service})
    open_ports.sort(key=lambda x: x["port"])
    closed_ports.sort(key=lambda x: x["port"])
    return {
        "result": {
            "host": host,
            "open": open_ports,
            "closed": closed_ports,
            "open_count": len(open_ports),
        }
    }




@mcp.tool()
def ssh_check(host: str, port: int = 22, timeout: int = 10) -> dict:
    """Check SSH server connectivity and retrieve the server banner (SSH version string, e.g. 'SSH-2.0-OpenSSH_8.9'). Does not attempt authentication."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "ssh_check"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "ssh_check"}
    timeout = min(max(1, timeout), 30)
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            raw = sock.recv(256)
            banner = raw.decode("utf-8", errors="replace").strip()
            try:
                sock.sendall(b"SSH-2.0-Claude_1.0\r\n")
            except Exception:
                pass
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "banner": banner,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "ssh_check", "host": host, "detail": type(e).__name__}


@mcp.tool()
def check_rdp(host: str, port: int = 3389, timeout: int = 10) -> dict:
    """Check whether a Remote Desktop Protocol (RDP) server is reachable by connecting and reading the X.224 Connection Confirm response. Does not authenticate. Returns whether the port is open and whether the server speaks RDP. Useful for verifying RDP is exposed or verifying VPN tunnel connectivity to Windows hosts."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_rdp"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "check_rdp"}
    timeout = min(max(1, timeout), 30)
    # X.224 Connection Request TPDU (COTP class 0, 11 bytes) over TPKT header
    # This is the standard RDP pre-negotiation probe
    _RDP_PROBE = bytes([
        0x03, 0x00, 0x00, 0x0b,  # TPKT: version=3, length=11
        0x06, 0xe0, 0x00, 0x00,  # TPDU: CR TPDU, dst=0, src=0
        0x00, 0x00, 0x00,        # class/options
    ])
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_RDP_PROBE)
            data = b""
            try:
                data = sock.recv(256)
            except socket.timeout:
                pass
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        # Valid TPKT+X.224 Connection Confirm: 0x03 0x00 (TPKT v3), then CC TPDU = 0xd0
        is_rdp = len(data) >= 6 and data[0] == 0x03 and data[1] == 0x00 and data[4] == 0xd0
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "rdp_response": is_rdp,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_rdp", "host": host, "detail": type(e).__name__}


@mcp.tool()
def imap_check(host: str, port: int = 143, timeout: int = 10) -> dict:
    """Check IMAP server connectivity. Reads server greeting and capabilities. Tests STARTTLS for port 143; uses implicit TLS for port 993. Does not authenticate."""
    import imaplib
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "imap_check"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "imap_check"}
    timeout = min(max(1, timeout), 30)
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        start = time.monotonic()
        if port == 993:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            imap = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
            tls = True
        else:
            imap = imaplib.IMAP4(host, port)
            tls = False

        greeting = (imap.welcome or b"").decode("utf-8", errors="replace").strip()
        caps = list(imap.capabilities) if imap.capabilities else []

        starttls = False
        if not tls and b"STARTTLS" in imap.capabilities:
            try:
                imap.starttls()
                starttls = True
            except Exception:
                pass
        try:
            imap.logout()
        except Exception:
            pass

        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "greeting": greeting,
                "capabilities": [c.decode("utf-8", errors="replace") for c in caps],
                "tls": tls,
                "starttls": starttls,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "imap_check", "host": host, "detail": type(e).__name__}
    finally:
        socket.setdefaulttimeout(old_timeout)


@mcp.tool()
def http_redirect_chain(url: str, max_redirects: int = 10, timeout: int = 10) -> dict:
    """Follow an HTTP/HTTPS URL through all redirects and return every hop with status code and Location header. Useful for debugging redirect loops or verifying HTTPS redirect configuration."""
    if not url or not url.strip():
        return {"error": "url must not be empty", "tool": "http_redirect_chain"}
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    max_redirects = min(max(1, max_redirects), 20)
    timeout = min(max(1, timeout), 30)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(_NoRedirect())
    chain = []
    current = url

    for hop in range(max_redirects + 1):
        try:
            req = urllib.request.Request(current, method="HEAD")
            try:
                resp = opener.open(req, timeout=timeout)
                chain.append({"hop": hop, "url": current, "status_code": resp.status, "final": True})
                break
            except urllib.error.HTTPError as e:
                location = e.headers.get("Location", "")
                chain.append({
                    "hop": hop,
                    "url": current,
                    "status_code": e.code,
                    "location": location,
                    "final": not location or e.code not in {301, 302, 303, 307, 308},
                })
                if not location or e.code not in {301, 302, 303, 307, 308}:
                    break
                if not location.startswith("http"):
                    location = urllib.parse.urljoin(current, location)
                current = location
        except Exception as e:
            chain.append({"hop": hop, "url": current, "error": str(e), "final": True})
            break
    else:
        chain.append({"hop": max_redirects + 1, "url": current, "error": "max_redirects exceeded", "final": True})

    return {
        "result": {
            "original_url": url,
            "final_url": current,
            "hop_count": len(chain),
            "chain": chain,
        }
    }



@mcp.tool()
def pop3_check(host: str, port: int = 110, timeout: int = 10) -> dict:
    """Check POP3 server connectivity. Reads server greeting and tests STARTTLS capability for port 110; uses implicit TLS for port 995. Does not authenticate."""
    import poplib
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "pop3_check"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "pop3_check"}
    timeout = min(max(1, timeout), 30)
    try:
        start = time.monotonic()
        if port == 995:
            pop = poplib.POP3_SSL(host, port, timeout=timeout)
            tls = True
        else:
            pop = poplib.POP3(host, port, timeout=timeout)
            tls = False

        greeting = (pop.getwelcome() or b"").decode("utf-8", errors="replace").strip()

        starttls = False
        if not tls:
            try:
                capa = pop.capa()
                if "STLS" in capa:
                    pop.stls()
                    starttls = True
            except Exception:
                pass

        try:
            pop.quit()
        except Exception:
            pass

        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "greeting": greeting,
                "tls": tls,
                "starttls": starttls,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "pop3_check", "host": host, "detail": type(e).__name__}


_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]


@mcp.tool()
def check_security_headers(url: str, timeout: int = 10) -> dict:
    """Fetch HTTP response headers and report which security headers are present or missing: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection. Returns a score."""
    if not url or not url.strip():
        return {"error": "url must not be empty", "tool": "check_security_headers"}
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    timeout = min(max(1, timeout), 30)
    try:
        req = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                status_code = resp.status
        except urllib.error.HTTPError as e:
            if e.code == 405:
                # Server doesn't support HEAD — retry with GET to get response headers
                req2 = urllib.request.Request(url, method="GET")
                try:
                    with urllib.request.urlopen(req2, timeout=timeout) as resp2:
                        headers = {k.lower(): v for k, v in resp2.headers.items()}
                        status_code = resp2.status
                except urllib.error.HTTPError as e2:
                    headers = {k.lower(): v for k, v in e2.headers.items()} if e2.headers else {}
                    status_code = e2.code
            else:
                headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
                status_code = e.code
    except Exception as e:
        return {"error": str(e), "tool": "check_security_headers", "url": url, "detail": type(e).__name__}

    present = {h: headers[h] for h in _SECURITY_HEADERS if h in headers}
    missing = [h for h in _SECURITY_HEADERS if h not in headers]
    return {
        "result": {
            "url": url,
            "status_code": status_code,
            "present": present,
            "missing": missing,
            "score": f"{len(present)}/{len(_SECURITY_HEADERS)}",
        }
    }



@mcp.tool()
def mysql_check(host: str, port: int = 3306, timeout: int = 5) -> dict:
    """Connect to a MySQL/MariaDB server and read the server greeting to extract the server version. Does not authenticate. Useful for verifying database server reachability and version."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "mysql_check"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "mysql_check"}
    timeout = min(max(1, timeout), 30)
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(1024)
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        # MySQL protocol: 4-byte packet length + 1-byte sequence, then protocol version byte,
        # then null-terminated server version string starting at byte 5.
        version = ""
        if len(data) > 5 and data[4] in (9, 10):
            null_pos = data.find(b"\x00", 5)
            if null_pos > 5:
                version = data[5:null_pos].decode("ascii", errors="replace")
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "server_version": version,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "mysql_check", "host": host, "detail": type(e).__name__}


@mcp.tool()
def redis_check(host: str, port: int = 6379, timeout: int = 5) -> dict:
    """Connect to a Redis server, send PING, and verify the +PONG response. Returns whether the server is up and responsive."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "redis_check"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "redis_check"}
    timeout = min(max(1, timeout), 30)
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            response = sock.recv(256).decode("utf-8", errors="replace").strip()
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "pong": response.startswith("+PONG"),
                "response": response,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "redis_check", "host": host, "detail": type(e).__name__}


@mcp.tool()
def ldap_check(host: str, port: int = 389, timeout: int = 5, use_tls: bool = False) -> dict:
    """Connect to an LDAP server and verify it responds with a valid LDAP response to a root DSE query. port: 389 (plain) or 636 (LDAPS). use_tls: wrap the connection in TLS (for LDAPS or STARTTLS). Returns whether the server is reachable and responding."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "ldap_check"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "ldap_check"}
    timeout = min(max(1, timeout), 30)
    _LDAP_BIND_REQUEST = bytes([
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02,
        0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
    ])
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            raw_sock.settimeout(timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=host)
            else:
                sock = raw_sock
            sock.sendall(_LDAP_BIND_REQUEST)
            banner = sock.recv(256)
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        is_ldap = len(banner) >= 2 and banner[0] == 0x30
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "ldap_response": is_ldap,
                "tls": use_tls,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except ssl.SSLError as e:
        return {"result": {"host": host, "port": port, "reachable": True, "ldap_response": False, "tls_error": str(e)}}
    except Exception as e:
        return {"error": str(e), "tool": "ldap_check", "host": host, "detail": type(e).__name__}


@mcp.tool()
def snmp_check(host: str, port: int = 161, timeout: int = 3, community: str = "public") -> dict:
    """Send an SNMPv2c GetRequest for sysDescr (OID 1.3.6.1.2.1.1.1.0) over UDP and verify the response. community: SNMP community string (default 'public'). Returns whether SNMP is reachable and the raw response bytes length."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "snmp_check"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "snmp_check"}
    timeout = min(max(1, timeout), 30)
    community_bytes = community.encode()
    community_len = len(community_bytes)
    community_field = bytes([0x04, community_len]) + community_bytes
    msg_inner = bytes([0x02, 0x01, 0x01]) + community_field + bytes([0xa0, 0x1c, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x05, 0x00])
    msg = bytes([0x30, len(msg_inner)]) + msg_inner
    try:
        start = time.monotonic()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(msg, (host, port))
            data, _ = sock.recvfrom(4096)
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        is_snmp = len(data) >= 2 and data[0] == 0x30
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "snmp_response": is_snmp,
                "response_bytes": len(data),
                "community": community,
                "elapsed_ms": elapsed_ms,
            }
        }
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout (no SNMP response — wrong community string or SNMP disabled)"}}
    except OSError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": str(e)}}
    except Exception as e:
        return {"error": str(e), "tool": "snmp_check", "host": host, "detail": type(e).__name__}


@mcp.tool()
def ping_sweep(network: str, timeout: int = 1) -> dict:
    """Ping all hosts in an IPv4 CIDR range and report which respond. Max /24 (256 addresses). Runs parallel pings. timeout: per-host wait in seconds. Returns list of alive IPs."""
    if not network or not network.strip():
        return {"error": "network must not be empty", "tool": "ping_sweep"}
    network = network.strip()
    timeout = min(max(1, timeout), 10)
    try:
        net = ipaddress.IPv4Network(network, strict=False)
    except ValueError as e:
        return {"error": str(e), "tool": "ping_sweep"}
    if net.num_addresses > 256:
        return {"error": f"Network too large ({net.num_addresses} addresses). Maximum /24 (256).", "tool": "ping_sweep"}

    if net.prefixlen <= 30:
        hosts = list(net.hosts())
    else:
        # /31 (RFC 3021 point-to-point) and /32 (host route): all addresses are usable
        hosts = [net.network_address + i for i in range(net.num_addresses)]

    def _ping_one(ip: str) -> tuple[str, bool]:
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), ip],
                capture_output=True,
                timeout=timeout + 2,
            )
            return ip, r.returncode == 0
        except Exception:
            return ip, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(hosts), 64)) as pool:
        results = list(pool.map(_ping_one, [str(h) for h in hosts]))

    alive = sorted(ip for ip, up in results if up)
    return {
        "result": {
            "network": str(net),
            "scanned": len(hosts),
            "alive_count": len(alive),
            "alive": alive,
        }
    }


_DNS_RESOLVERS = {
    "google": "8.8.8.8",
    "cloudflare": "1.1.1.1",
    "quad9": "9.9.9.9",
    "opendns": "208.67.222.222",
}


@mcp.tool()
def dns_propagation(domain: str, record_type: str = "A") -> dict:
    """Check DNS propagation across 4 major public resolvers (Google 8.8.8.8, Cloudflare 1.1.1.1, Quad9 9.9.9.9, OpenDNS 208.67.222.222). Reports records from each and whether they are consistent. Useful after DNS changes to verify global propagation."""
    if not domain or not domain.strip():
        return {"error": "domain must not be empty", "tool": "dns_propagation"}
    domain = domain.strip()
    record_type = record_type.strip().upper()
    if record_type not in _VALID_RECORD_TYPES:
        return {"error": f"Invalid record type '{record_type}'. Valid: {', '.join(sorted(_VALID_RECORD_TYPES))}", "tool": "dns_propagation"}

    results: dict = {}
    for name, ns_ip in _DNS_RESOLVERS.items():
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns_ip]
            resolver.lifetime = 5.0
            answers = resolver.resolve(domain, record_type)
            results[name] = {
                "nameserver": ns_ip,
                "records": sorted(str(r) for r in answers),
                "ttl": answers.rrset.ttl if answers.rrset else None,
            }
        except dns.resolver.NXDOMAIN:
            results[name] = {"nameserver": ns_ip, "error": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            results[name] = {"nameserver": ns_ip, "records": [], "note": "no records of this type"}
        except Exception as e:
            results[name] = {"nameserver": ns_ip, "error": str(e)}

    record_sets = [tuple(v["records"]) for v in results.values() if "records" in v and not v.get("error")]
    has_errors = any("error" in v for v in results.values())
    consistent = bool(record_sets) and len(set(record_sets)) == 1 and not has_errors

    return {
        "result": {
            "domain": domain,
            "record_type": record_type,
            "consistent": consistent,
            "propagated": consistent and len(record_sets) == len(_DNS_RESOLVERS),
            "resolvers": results,
        }
    }



@mcp.tool()
def local_ports(protocol: str = "all", show_processes: bool = True) -> dict:
    """List listening TCP and UDP ports on the local machine. protocol: 'tcp', 'udp', or 'all'. show_processes: include process names (requires root on some systems; set to false to skip). Uses ss (Linux) with fallback to netstat."""
    if protocol not in {"tcp", "udp", "all"}:
        return {"error": "protocol must be 'tcp', 'udp', or 'all'", "tool": "local_ports"}
    flags = {"tcp": "-tln", "udp": "-uln", "all": "-tuln"}[protocol]
    try:
        cmd = ["ss", flags, "-p"] if show_processes else ["ss", flags]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise FileNotFoundError
        entries = []
        for line in result.stdout.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].lower().replace("*", "").strip()
            local = parts[4] if len(parts) > 4 else ""
            process = parts[6] if show_processes and len(parts) > 6 else ""
            entries.append({"protocol": proto, "local_address": local, "process": process})
        if show_processes and all(e["process"] == "" for e in entries) and entries:
            return {"result": {"entries": entries, "count": len(entries), "note": "Process info unavailable (run as root for process names)"}}
        return {"result": {"entries": entries, "count": len(entries)}}
    except FileNotFoundError:
        try:
            result2 = subprocess.run(["netstat", "-tuln"], capture_output=True, text=True, timeout=10)
            entries2 = []
            for line in result2.stdout.strip().splitlines()[2:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                entries2.append({"protocol": parts[0], "local_address": parts[3], "state": parts[5] if len(parts) > 5 else ""})
            return {"result": {"entries": entries2, "count": len(entries2)}}
        except Exception as e2:
            return {"error": str(e2), "tool": "local_ports"}
    except Exception as e:
        return {"error": str(e), "tool": "local_ports", "detail": type(e).__name__}


@mcp.tool()
def network_interfaces() -> dict:
    """List all local network interfaces with their IP addresses, subnet prefix length, and link state. Structured output from 'ip addr' (Linux) or 'ifconfig' (macOS/BSD)."""
    try:
        result = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            import json as _json
            ifaces = _json.loads(result.stdout)
            out = []
            for iface in ifaces:
                addrs = [
                    {"address": a["local"], "prefix": a.get("prefixlen"), "family": a.get("family", "")}
                    for a in iface.get("addr_info", [])
                ]
                out.append({
                    "name": iface.get("ifname"),
                    "state": iface.get("operstate", "").upper(),
                    "mac": iface.get("address"),
                    "mtu": iface.get("mtu"),
                    "addresses": addrs,
                })
            return {"result": out}
    except Exception:
        pass
    try:
        result2 = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10)
        return {"result": {"raw_output": result2.stdout}}
    except Exception as e:
        return {"error": str(e), "tool": "network_interfaces", "detail": type(e).__name__}

@mcp.tool()
def bgp_lookup(ip: str) -> dict:
    """Look up BGP/ASN information for a public IP address using Team Cymru's WHOIS service. Returns the ASN, BGP prefix, country, registry, allocation date, and AS organization name. Useful for network forensics, attributing IPs to organizations, and tracing routing paths."""
    if not ip or not ip.strip():
        return {"error": "ip must not be empty", "tool": "bgp_lookup"}
    ip = ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"error": f"Invalid IP address: '{ip}'", "tool": "bgp_lookup"}
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return {"error": f"'{ip}' is a private/reserved address; BGP lookup is only meaningful for public IPs", "tool": "bgp_lookup"}
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=10) as s:
            s.sendall(f" -v {ip}\r\n".encode())
            chunks = []
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        lines = b"".join(chunks).decode("utf-8", errors="replace").strip().splitlines()
        result_line = next((ln for ln in lines if "|" in ln and not ln.strip().startswith("AS")), None)
        if not result_line:
            return {"result": {"ip": ip, "asn": None, "prefix": None, "raw": lines}}
        parts = [p.strip() for p in result_line.split("|")]
        return {
            "result": {
                "ip": ip,
                "asn": parts[0] if len(parts) > 0 else None,
                "prefix": parts[2] if len(parts) > 2 else None,
                "country": parts[3] if len(parts) > 3 else None,
                "registry": parts[4] if len(parts) > 4 else None,
                "allocated": parts[5] if len(parts) > 5 else None,
                "organization": parts[6] if len(parts) > 6 else None,
            }
        }
    except Exception as e:
        return {"error": str(e), "tool": "bgp_lookup", "ip": ip, "detail": type(e).__name__}


@mcp.tool()
def tls_version_check(host: str, port: int = 443, timeout: int = 10) -> dict:
    """Test which TLS protocol versions a server accepts (TLS 1.2, TLS 1.3). Also returns the negotiated cipher suite and certificate subject for each accepted version. Useful for security audits — TLS 1.0 and 1.1 should be disabled."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "tls_version_check"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "tls_version_check"}
    timeout = min(max(1, timeout), 30)
    results: dict = {}
    version_map = {
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    for version_name, tls_version in version_map.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((host, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cipher = tls_sock.cipher()
                    cert = tls_sock.getpeercert()
                    subject = dict(x[0] for x in cert.get("subject", [()])) if cert else {}
                    results[version_name] = {
                        "accepted": True,
                        "cipher": cipher[0] if cipher else None,
                        "bits": cipher[2] if cipher else None,
                        "common_name": subject.get("commonName"),
                    }
        except ssl.SSLError as e:
            results[version_name] = {"accepted": False, "reason": str(e)}
        except Exception as e:
            results[version_name] = {"accepted": False, "reason": str(e)}
    return {
        "result": {
            "host": host,
            "port": port,
            "versions": results,
            "tls12_accepted": results.get("TLSv1.2", {}).get("accepted", False),
            "tls13_accepted": results.get("TLSv1.3", {}).get("accepted", False),
        }
    }


@mcp.tool()
def cert_check_bulk(hosts: str, port: int = 443, timeout: int = 10) -> dict:
    """Check TLS certificates for multiple hosts in one call. hosts: comma-separated hostnames (max 20). Returns expiry, days remaining, issuer, SANs, and validity for each. Useful for monitoring certificate renewals across many domains at once."""
    if not hosts or not hosts.strip():
        return {"error": "hosts must not be empty", "tool": "cert_check_bulk"}
    hosts = hosts.strip()
    host_list = [h.strip() for h in hosts.split(",") if h.strip()]
    if not host_list:
        return {"error": "No valid hosts specified", "tool": "cert_check_bulk"}
    if len(host_list) > 20:
        return {"error": f"Too many hosts ({len(host_list)}). Maximum 20 per call.", "tool": "cert_check_bulk"}
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "cert_check_bulk"}
    timeout = min(max(1, timeout), 60)

    def _check_one(host: str) -> tuple[str, dict]:
        fmt = "%b %d %H:%M:%S %Y %Z"
        try:
            # Strip port suffix for SNI (e.g. "example.com:443" → "example.com")
            sni = host
            if ":" in host and not host.startswith("["):
                maybe_host, maybe_port = host.rsplit(":", 1)
                if maybe_port.isdigit():
                    sni = maybe_host
            ctx = ssl.create_default_context()
            with socket.socket() as raw:
                raw.settimeout(timeout)
                with ctx.wrap_socket(raw, server_hostname=sni) as s:
                    s.connect((sni, port))
                    cert = s.getpeercert()
            not_after = datetime.strptime(cert["notAfter"], fmt).replace(tzinfo=timezone.utc)
            days = (not_after - datetime.now(timezone.utc)).days
            return host, {
                "expires": cert["notAfter"],
                "days_remaining": days,
                "valid": days > 0,
                "verified": True,
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "san": [v for _, v in cert.get("subjectAltName", [])],
            }
        except ssl.SSLCertVerificationError as e:
            return host, {"verified": False, "ssl_error": str(e)}
        except Exception as e:
            return host, {"error": str(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(host_list), 10)) as pool:
        future_to_host = {pool.submit(_check_one, h): h for h in host_list}
        results = {}
        for f in concurrent.futures.as_completed(future_to_host):
            h, data = f.result()
            results[h] = data

    expiring_soon = [
        h for h, d in results.items()
        if isinstance(d.get("days_remaining"), int) and 0 < d["days_remaining"] <= 30
    ]
    return {"result": {"port": port, "hosts": results, "expiring_soon_30d": expiring_soon}}


@mcp.tool()
def check_sip(host: str, port: int = 5060, timeout: int = 5, transport: str = "udp") -> dict:
    """Check a SIP (Session Initiation Protocol) server by sending an OPTIONS probe. port: default 5060 (UDP/TCP) or 5061 (TLS). transport: 'udp' (default) or 'tcp'. Returns whether the server is reachable and responds with a valid SIP message. Useful for verifying VoIP server health."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_sip"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "check_sip"}
    transport = transport.strip().lower()
    if transport not in {"udp", "tcp"}:
        return {"error": "transport must be 'udp' or 'tcp'", "tool": "check_sip"}
    timeout = min(max(1, timeout), 30)
    # Minimal SIP OPTIONS probe (RFC 3261)
    call_id = f"mcp-nettools-sip-check@{host}"
    sip_msg = (
        f"OPTIONS sip:{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/{'UDP' if transport == 'udp' else 'TCP'} 127.0.0.1:5060;branch=z9hG4bK-probe\r\n"
        f"Max-Forwards: 1\r\n"
        f"To: <sip:{host}>\r\n"
        f"From: <sip:probe@127.0.0.1>;tag=mcp-probe\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()
    try:
        start = time.monotonic()
        if transport == "udp":
            addrinfos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
            if not addrinfos:
                return {"result": {"host": host, "port": port, "reachable": False, "reason": "DNS resolution failed"}}
            af, _, _, _, addr = addrinfos[0]
            with socket.socket(af, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(sip_msg, addr)
                try:
                    data, _ = sock.recvfrom(4096)
                    response = data.decode("utf-8", errors="replace")
                except socket.timeout:
                    return {"result": {"host": host, "port": port, "transport": transport, "reachable": False, "reason": "no response (UDP timeout)"}}
        else:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(sip_msg)
                try:
                    data = sock.recv(4096)
                    response = data.decode("utf-8", errors="replace")
                except socket.timeout:
                    response = ""
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        is_sip = response.startswith("SIP/2.0")
        status_line = response.split("\r\n")[0] if is_sip else ""
        return {
            "result": {
                "host": host,
                "port": port,
                "transport": transport,
                "reachable": True,
                "sip_response": is_sip,
                "status_line": status_line,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "transport": transport, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "transport": transport, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_sip", "host": host, "detail": type(e).__name__}


@mcp.tool()
def dnssec_check(domain: str, nameserver: str = "") -> dict:
    """Check DNSSEC status for a domain: whether DNSKEY records are published, RRSIG signatures are present on A records, and the DS (Delegation Signer) record exists in the parent zone. Returns key algorithm, key tag, and whether validation appears correct. nameserver: optional custom resolver IP."""
    if not domain or not domain.strip():
        return {"error": "domain must not be empty", "tool": "dnssec_check"}
    domain = domain.strip()
    if nameserver and nameserver.strip():
        try:
            ipaddress.ip_address(nameserver.strip())
        except ValueError:
            return {"error": f"Invalid nameserver IP: '{nameserver}'", "tool": "dnssec_check"}
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10.0
        if nameserver and nameserver.strip():
            resolver.nameservers = [nameserver.strip()]
        result: dict = {"domain": domain, "dnskey": False, "rrsig_a": False, "ds": False}
        try:
            dnskey_answers = resolver.resolve(domain, "DNSKEY")
            result["dnskey"] = True
            keys = []
            for rdata in dnskey_answers:
                flags = rdata.flags
                protocol = rdata.protocol
                algorithm = rdata.algorithm
                keys.append({"flags": flags, "protocol": protocol, "algorithm": int(algorithm)})
            result["dnskey_records"] = keys
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            result["dnskey_records"] = []
        except Exception as e:
            result["dnskey_error"] = str(e)
        try:
            rrsig_answers = resolver.resolve(domain, "RRSIG")
            result["rrsig_a"] = True
            result["rrsig_count"] = len(list(rrsig_answers))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            result["rrsig_count"] = 0
        except Exception as e:
            result["rrsig_error"] = str(e)
        try:
            ds_answers = resolver.resolve(domain, "DS")
            result["ds"] = True
            ds_records = []
            for rdata in ds_answers:
                ds_records.append({"key_tag": rdata.key_tag, "algorithm": int(rdata.algorithm), "digest_type": rdata.digest_type})
            result["ds_records"] = ds_records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            result["ds_records"] = []
        except Exception as e:
            result["ds_error"] = str(e)
        result["dnssec_enabled"] = result["dnskey"] and result["rrsig_a"] and result["ds"]
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "dnssec_check", "domain": domain, "detail": type(e).__name__}


@mcp.tool()
def check_mongodb(host: str, port: int = 27017, timeout: int = 5) -> dict:
    """Connect to a MongoDB server and send a hello command via the MongoDB wire protocol (OP_MSG). Returns whether the server is reachable and responds as a MongoDB instance. Does not authenticate. Useful for verifying MongoDB/Atlas-compatible server availability."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_mongodb"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "check_mongodb"}
    timeout = min(max(1, timeout), 30)
    # Build OP_MSG hello command: {"hello": 1, "$db": "admin"}
    hello_key = b"hello\x00"
    db_key = b"$db\x00"
    admin_str = b"admin\x00"
    doc_body = b"\x10" + hello_key + struct.pack("<i", 1)  # int32 hello=1
    doc_body += b"\x02" + db_key + struct.pack("<i", len(admin_str)) + admin_str  # string $db="admin"
    doc_len = 4 + len(doc_body) + 1
    bson_doc = struct.pack("<i", doc_len) + doc_body + b"\x00"
    msg_body = struct.pack("<I", 0) + b"\x00" + bson_doc  # flagBits=0, sectionType=0
    msg_len = 16 + len(msg_body)
    wire_msg = struct.pack("<iiii", msg_len, 1, 0, 2013) + msg_body
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(wire_msg)
            response = sock.recv(4096)
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        is_mongodb = False
        if len(response) >= 16:
            _, _, _, op_code = struct.unpack("<iiii", response[:16])
            is_mongodb = op_code in (1, 2013)
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "mongodb_response": is_mongodb,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_mongodb", "host": host, "detail": type(e).__name__}


@mcp.tool()
def check_vnc(host: str, port: int = 5900, timeout: int = 5) -> dict:
    """Connect to a VNC server and read the RFB protocol banner. Returns whether the server is reachable, the RFB version string (e.g. 'RFB 003.008'), and the supported security types. Does not authenticate. port: 5900 (default), 5901, 5902, etc. Useful for verifying remote desktop service availability."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_vnc"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "check_vnc"}
    timeout = min(max(1, timeout), 30)
    _SECURITY_TYPES = {0: "invalid", 1: "none", 2: "vnc_auth", 5: "ra2", 6: "ra2ne", 16: "tight", 17: "ultra", 18: "tls", 19: "vencrypt", 20: "gtk_vnc_sasl", 21: "md5", 22: "xvp"}
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner_raw = sock.recv(12)
            banner = banner_raw.decode("utf-8", errors="replace").rstrip("\n")
            security_types = []
            if banner.startswith("RFB "):
                # Read security type list (RFB 3.7+): 1 byte count, then count bytes
                try:
                    count_byte = sock.recv(1)
                    if count_byte and count_byte[0] > 0:
                        type_bytes = sock.recv(count_byte[0])
                        for t in type_bytes:
                            security_types.append({"code": t, "name": _SECURITY_TYPES.get(t, f"type_{t}")})
                except Exception:
                    pass
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        is_vnc = banner.startswith("RFB ")
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "vnc_response": is_vnc,
                "rfb_version": banner,
                "security_types": security_types,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_vnc", "host": host, "detail": type(e).__name__}


@mcp.tool()
def check_postgres(host: str, port: int = 5432, timeout: int = 5) -> dict:
    """Connect to a PostgreSQL server and read the server version from the startup response. Does not authenticate. Useful for verifying database server reachability and version."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_postgres"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "check_postgres"}
    timeout = min(max(1, timeout), 30)
    # PostgreSQL v3.0 startup message: length(4) + version(4) + key=value pairs + \0
    params = b"user\x00postgres\x00database\x00postgres\x00\x00"
    msg_body = struct.pack("!I", 196608) + params
    msg = struct.pack("!I", len(msg_body) + 4) + msg_body
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(msg)
            data = sock.recv(4096)
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        server_version = None
        i = 0
        while i < len(data):
            if i + 5 > len(data):
                break
            msg_type = chr(data[i])
            msg_len = struct.unpack("!I", data[i+1:i+5])[0]
            msg_data = data[i+5:i+1+msg_len]
            if msg_type == "S":
                null_pos = msg_data.find(b"\x00")
                if null_pos >= 0:
                    name = msg_data[:null_pos].decode("utf-8", errors="replace")
                    val_start = null_pos + 1
                    null_pos2 = msg_data.find(b"\x00", val_start)
                    value = msg_data[val_start:null_pos2].decode("utf-8", errors="replace") if null_pos2 >= 0 else ""
                    if name == "server_version":
                        server_version = value
            i += 1 + msg_len
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "server_version": server_version,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_postgres", "host": host, "detail": type(e).__name__}


@mcp.tool()
def check_memcached(host: str, port: int = 11211, timeout: int = 5) -> dict:
    """Connect to a Memcached server and request its version. Returns whether the server is reachable and its version string. Useful for verifying caching layer availability."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_memcached"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "check_memcached"}
    timeout = min(max(1, timeout), 30)
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"version\r\n")
            response = sock.recv(256).decode("utf-8", errors="replace").strip()
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        version = None
        if response.startswith("VERSION "):
            version = response.split(" ", 1)[1].strip()
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "version": version,
                "response": response,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_memcached", "host": host, "detail": type(e).__name__}


@mcp.tool()
def check_mqtt(host: str, port: int = 1883, timeout: int = 5, client_id: str = "mcp-probe") -> dict:
    """Connect to an MQTT broker and send a CONNECT packet (v3.1.1). Checks for a CONNACK response and decodes the return code. port: 1883 (plain) or 8883 (TLS). Does not authenticate (anonymous connect). Returns whether the broker accepted the connection and its return code."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_mqtt"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "check_mqtt"}
    timeout = min(max(1, timeout), 30)
    client_id_bytes = (client_id.strip() or "mcp-probe").encode("utf-8")
    # MQTT v3.1.1 CONNECT variable header + payload
    variable_header = (
        b"\x00\x04MQTT"  # protocol name
        b"\x04"          # protocol level = 3.1.1
        b"\x02"          # connect flags: clean session
        b"\x00\x3c"      # keep-alive: 60s
    )
    payload = struct.pack("!H", len(client_id_bytes)) + client_id_bytes
    remaining = variable_header + payload
    connect_pkt = bytes([0x10, len(remaining)]) + remaining
    _CONNACK_CODES = {0: "accepted", 1: "refused: unacceptable protocol", 2: "refused: client ID rejected", 3: "refused: server unavailable", 4: "refused: bad credentials", 5: "refused: not authorized"}
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(connect_pkt)
            response = sock.recv(64)
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        # CONNACK: 0x20 0x02 session_present return_code
        is_mqtt = len(response) >= 4 and response[0] == 0x20 and response[1] == 0x02
        return_code = response[3] if is_mqtt else None
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "mqtt_response": is_mqtt,
                "accepted": return_code == 0 if is_mqtt else None,
                "return_code": return_code,
                "return_code_text": _CONNACK_CODES.get(return_code) if return_code is not None else None,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_mqtt", "host": host, "detail": type(e).__name__}


@mcp.tool()
def check_spf(domain: str, nameserver: str = "") -> dict:
    """Check the SPF (Sender Policy Framework) record for a domain. Looks up TXT records at the domain root and extracts the v=spf1 policy. nameserver: optional custom resolver IP. Multiple SPF records is a misconfiguration (RFC 7208 §3.2)."""
    if not domain or not domain.strip():
        return {"error": "domain must not be empty", "tool": "check_spf"}
    domain = domain.strip()
    if nameserver and nameserver.strip():
        try:
            ipaddress.ip_address(nameserver.strip())
        except ValueError:
            return {"error": f"Invalid nameserver IP: '{nameserver}'", "tool": "check_spf"}
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10.0
        if nameserver and nameserver.strip():
            resolver.nameservers = [nameserver.strip()]
        answers = resolver.resolve(domain, "TXT")
        spf_records = []
        for rdata in answers:
            txt = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
            if txt.startswith("v=spf1"):
                spf_records.append(txt)
        if not spf_records:
            return {"result": {"domain": domain, "spf_found": False, "record": None}}
        return {
            "result": {
                "domain": domain,
                "spf_found": True,
                "record": spf_records[0],
                "multiple_records": len(spf_records) > 1,
                "all_records": spf_records,
            }
        }
    except dns.resolver.NXDOMAIN:
        return {"result": {"domain": domain, "spf_found": False, "error": "NXDOMAIN — domain does not exist"}}
    except dns.resolver.NoAnswer:
        return {"result": {"domain": domain, "spf_found": False, "record": None}}
    except Exception as e:
        return {"error": str(e), "tool": "check_spf", "domain": domain, "detail": type(e).__name__}


@mcp.tool()
def check_dkim(domain: str, selector: str, nameserver: str = "") -> dict:
    """Check whether a DKIM public key is published for a domain and selector. Looks up the TXT record at selector._domainkey.domain. selector: DKIM selector name (e.g. 'google', 'mail', 'default', 's1'). nameserver: optional custom resolver IP."""
    if not domain or not domain.strip():
        return {"error": "domain must not be empty", "tool": "check_dkim"}
    domain = domain.strip()
    if not selector or not selector.strip():
        return {"error": "selector must not be empty", "tool": "check_dkim"}
    selector = selector.strip()
    if nameserver and nameserver.strip():
        try:
            ipaddress.ip_address(nameserver.strip())
        except ValueError:
            return {"error": f"Invalid nameserver IP: '{nameserver}'", "tool": "check_dkim"}
    dkim_host = f"{selector}._domainkey.{domain}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10.0
        if nameserver and nameserver.strip():
            resolver.nameservers = [nameserver.strip()]
        answers = resolver.resolve(dkim_host, "TXT")
        records = []
        for rdata in answers:
            txt = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
            records.append(txt)
        dkim_record = next((r for r in records if "v=DKIM1" in r or "p=" in r), None)
        return {
            "result": {
                "domain": domain,
                "selector": selector,
                "dkim_host": dkim_host,
                "dkim_found": bool(dkim_record),
                "record": dkim_record,
                "all_txt_records": records,
            }
        }
    except dns.resolver.NXDOMAIN:
        return {"result": {"domain": domain, "selector": selector, "dkim_host": dkim_host, "dkim_found": False, "error": "NXDOMAIN — selector not found"}}
    except dns.resolver.NoAnswer:
        return {"result": {"domain": domain, "selector": selector, "dkim_host": dkim_host, "dkim_found": False, "record": None}}
    except Exception as e:
        return {"error": str(e), "tool": "check_dkim", "domain": domain, "detail": type(e).__name__}


@mcp.tool()
def check_dmarc(domain: str, nameserver: str = "") -> dict:
    """Check the DMARC policy for a domain. Looks up the TXT record at _dmarc.domain and parses the policy tags: p (domain policy: none/quarantine/reject), sp (subdomain policy), rua (aggregate report URI), ruf (forensic report URI), adkim (DKIM alignment: r=relaxed/s=strict), aspf (SPF alignment), pct (percentage of messages subject to policy). nameserver: optional custom resolver IP."""
    if not domain or not domain.strip():
        return {"error": "domain must not be empty", "tool": "check_dmarc"}
    domain = domain.strip()
    if nameserver and nameserver.strip():
        try:
            ipaddress.ip_address(nameserver.strip())
        except ValueError:
            return {"error": f"Invalid nameserver IP: '{nameserver}'", "tool": "check_dmarc"}
    dmarc_host = f"_dmarc.{domain}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10.0
        if nameserver and nameserver.strip():
            resolver.nameservers = [nameserver.strip()]
        answers = resolver.resolve(dmarc_host, "TXT")
        records = []
        for rdata in answers:
            txt = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
            records.append(txt)
        dmarc_record = next((r for r in records if r.startswith("v=DMARC1")), None)
        if not dmarc_record:
            return {"result": {"domain": domain, "dmarc_host": dmarc_host, "dmarc_found": False, "record": None}}
        tags: dict = {}
        for part in dmarc_record.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                tags[k.strip()] = v.strip()
        return {
            "result": {
                "domain": domain,
                "dmarc_host": dmarc_host,
                "dmarc_found": True,
                "record": dmarc_record,
                "policy": tags.get("p"),
                "subdomain_policy": tags.get("sp"),
                "rua": tags.get("rua"),
                "ruf": tags.get("ruf"),
                "adkim": tags.get("adkim", "r"),
                "aspf": tags.get("aspf", "r"),
                "pct": tags.get("pct", "100"),
                "tags": tags,
            }
        }
    except dns.resolver.NXDOMAIN:
        return {"result": {"domain": domain, "dmarc_host": dmarc_host, "dmarc_found": False, "error": "NXDOMAIN — _dmarc record not found"}}
    except dns.resolver.NoAnswer:
        return {"result": {"domain": domain, "dmarc_host": dmarc_host, "dmarc_found": False, "record": None}}
    except Exception as e:
        return {"error": str(e), "tool": "check_dmarc", "domain": domain, "detail": type(e).__name__}


@mcp.tool()
def check_vault(host: str, port: int = 8200, timeout: int = 5, https: bool = True) -> dict:
    """Check HashiCorp Vault server health. Returns initialized/sealed/standby state and Vault version. Handles all Vault health status codes: 200=active, 429=standby, 472=DR secondary active, 473=performance standby, 501=uninitialized, 503=sealed. host: IP or hostname. port: default 8200. https: use HTTPS (default True — Vault almost always runs HTTPS; set False for dev mode)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_vault"}
    host = host.strip()
    scheme = "https" if https else "http"
    url = f"{scheme}://{host}:{port}/v1/sys/health"
    _state_map = {200: "active", 429: "standby", 472: "dr_secondary_active", 473: "performance_standby", 501: "uninitialized", 503: "sealed"}
    try:
        ctx = None
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        status_code = 200
        data: dict = {}
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                status_code = resp.status
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            status_code = e.code
            try:
                data = json.loads(e.read().decode())
            except Exception:
                pass
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "state": _state_map.get(status_code, f"unknown_{status_code}"),
                "status_code": status_code,
                "initialized": data.get("initialized"),
                "sealed": data.get("sealed"),
                "standby": data.get("standby"),
                "version": data.get("version"),
                "cluster_name": data.get("cluster_name"),
            }
        }
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_vault", "detail": type(e).__name__}


@mcp.tool()
def check_zookeeper(host: str, port: int = 2181, timeout: int = 5) -> dict:
    """Check ZooKeeper server health using the 'ruok' four-letter word command. Also attempts 'stat' to return mode (leader/follower/standalone) and client count. host: IP or hostname. port: default 2181."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_zookeeper"}
    host = host.strip()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(b"ruok")
            ruok_resp = s.recv(64).decode(errors="replace").strip()
        result: dict = {"host": host, "port": port, "reachable": True, "ruok": ruok_resp, "healthy": ruok_resp == "imok"}
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.sendall(b"stat")
                raw = b""
                s.settimeout(2.0)
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
            stat_text = raw.decode(errors="replace")
            for line in stat_text.splitlines():
                stripped = line.strip()
                if stripped.startswith("Mode:"):
                    result["mode"] = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("Connections:"):
                    try:
                        result["connections"] = int(stripped.split(":", 1)[1].strip())
                    except ValueError:
                        pass
        except Exception:
            pass
        return {"result": result}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "error": "connection timed out"}}
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "error": "connection refused"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_zookeeper", "detail": type(e).__name__}


@mcp.tool()
def check_elasticsearch(host: str, port: int = 9200, timeout: int = 5, https: bool = False) -> dict:
    """Connect to an Elasticsearch or OpenSearch node and check cluster health. Returns cluster name, status (green/yellow/red), node counts, shard counts, and unassigned shards. host: IP or hostname. port: default 9200. https: use HTTPS instead of HTTP (default False)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_elasticsearch"}
    host = host.strip()
    scheme = "https" if https else "http"
    url = f"{scheme}://{host}:{port}/_cluster/health"
    try:
        ctx = ssl.create_default_context() if https else None
        if ctx and https:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "cluster_name": data.get("cluster_name"),
                "status": data.get("status"),
                "number_of_nodes": data.get("number_of_nodes"),
                "number_of_data_nodes": data.get("number_of_data_nodes"),
                "active_primary_shards": data.get("active_primary_shards"),
                "active_shards": data.get("active_shards"),
                "relocating_shards": data.get("relocating_shards"),
                "unassigned_shards": data.get("unassigned_shards"),
                "timed_out": data.get("timed_out"),
            }
        }
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_elasticsearch", "detail": type(e).__name__}


@mcp.tool()
def check_etcd(host: str, port: int = 2379, timeout: int = 5) -> dict:
    """Check etcd v3 cluster health via its HTTP health endpoint. Returns health status and reason if unhealthy. host: IP or hostname. port: default 2379 (etcd client port)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_etcd"}
    host = host.strip()
    url = f"http://{host}:{port}/health"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "health": data.get("health"),
                "reason": data.get("reason"),
            }
        }
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode())
        except Exception:
            data = {}
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "status_code": e.code,
                "health": data.get("health", "false"),
                "reason": data.get("reason", e.reason),
            }
        }
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_etcd", "detail": type(e).__name__}


@mcp.tool()
def check_consul(host: str, port: int = 8500, timeout: int = 5) -> dict:
    """Check Consul agent health and cluster leader. Returns agent node name, datacenter, server/client role, leader address, and Consul version. host: IP or hostname. port: default 8500 (Consul HTTP API port)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_consul"}
    host = host.strip()
    base = f"http://{host}:{port}"
    try:
        with urllib.request.urlopen(urllib.request.Request(f"{base}/v1/status/leader"), timeout=timeout) as r:
            leader = r.read().decode().strip().strip('"')
        try:
            with urllib.request.urlopen(urllib.request.Request(f"{base}/v1/agent/self"), timeout=timeout) as r:
                agent = json.loads(r.read().decode())
        except Exception:
            agent = {}
        config = agent.get("Config", {})
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "leader": leader,
                "node_name": config.get("NodeName"),
                "datacenter": config.get("Datacenter"),
                "server": config.get("Server"),
                "version": config.get("Version"),
            }
        }
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_consul", "detail": type(e).__name__}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
