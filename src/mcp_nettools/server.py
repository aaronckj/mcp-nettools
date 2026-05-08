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
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "port_check"}
    timeout = min(max(1, timeout), 300)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return {"result": {"host": host, "port": port, "open": True}}
    except (ConnectionRefusedError, TimeoutError):
        return {"result": {"host": host, "port": port, "open": False}}
    except OSError as e:
        return {"error": str(e), "tool": "port_check", "host": host, "port": port}


@mcp.tool()
def port_scan(host: str, ports: str, timeout: int = 3, open_only: bool = False) -> dict:
    """Check multiple TCP ports on a host. ports: comma-separated or ranges (e.g., '22,80,443,8000-8080'). Max 500 ports. timeout: 1-30 s. open_only: if True, omit closed ports from the 'ports' dict (useful for large ranges)."""
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
    ports_dict = {str(k): v for k, v in sorted(results.items()) if not open_only or v == "open"}
    return {
        "result": {
            "host": host,
            "scanned": len(port_list),
            "open_count": len(open_ports),
            "open": open_ports,
            "ports": ports_dict,
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
        # Cert exists but chain/expiry invalid — retry with CERT_OPTIONAL (not CERT_NONE) so
        # getpeercert() returns the parsed cert dict instead of an empty dict.
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_OPTIONAL
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
        return {"error": str(e), "tool": "http_check", "url": url, "detail": type(e).__name__}


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
            "mac": mac,
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
        return {"error": str(e), "tool": "smtp_check", "host": host, "port": port}
    except Exception as e:
        return {"error": str(e), "tool": "smtp_check", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_ldap(host: str, port: int = 389, timeout: int = 5, use_ssl: bool = False) -> dict:
    """Check LDAP server connectivity and verify it speaks the LDAP protocol. Sends an anonymous LDAPv3 bind request and checks for a valid response. port: 389 (LDAP), 636 (LDAPS). use_ssl: connect with TLS (default False; automatically True for port 636). Does not authenticate — anonymous bind only."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_ldap"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "check_ldap"}
    timeout = min(max(1, timeout), 30)
    if port == 636:
        use_ssl = True
    # Anonymous LDAPv3 bind request (BER-encoded)
    # BindRequest: version=3, name="", authentication=simple("")
    bind_req = bytes([
        0x30, 0x0c,             # SEQUENCE, length 12
        0x02, 0x01, 0x01,       # INTEGER messageID=1
        0x60, 0x07,             # APPLICATION 0 (BindRequest), length 7
        0x02, 0x01, 0x03,       # INTEGER version=3
        0x04, 0x00,             # OCTET STRING name="" (empty DN)
        0x80, 0x00,             # CONTEXT [0] simple="" (empty password)
    ])
    try:
        start = time.monotonic()
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        raw_sock.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock
        with sock:
            sock.sendall(bind_req)
            response = sock.recv(1024)
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        # Check response is a valid LDAP BindResponse (0x61 = APPLICATION 1)
        is_ldap = len(response) >= 4 and response[0] == 0x30 and 0x61 in response
        result_code = None
        if is_ldap:
            # Find the BindResponse tag and extract result code
            idx = response.find(0x61)
            if idx >= 0 and idx + 4 < len(response):
                enum_idx = response.find(0x0a, idx)
                if enum_idx >= 0 and enum_idx + 2 < len(response):
                    result_code = response[enum_idx + 2]
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "ldap_response": is_ldap,
                "bind_result_code": result_code,
                "bind_success": result_code == 0,
                "tls": use_ssl,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_ldap", "host": host, "port": port, "detail": type(e).__name__}


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
            return {"error": "NTP response too short — server may not speak NTP", "tool": "ntp_check", "host": host, "port": port}
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
        return {"error": str(e), "tool": "ntp_check", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "ftp_check", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "tcp_banner", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "ssh_check", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "check_rdp", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "imap_check", "host": host, "port": port, "detail": type(e).__name__}
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
        return {"error": str(e), "tool": "pop3_check", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "mysql_check", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "redis_check", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "ldap_check", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "snmp_check", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def ping_sweep(network: str, timeout: int = 1) -> dict:
    """Ping all hosts in an IPv4 CIDR range and report which respond. Max /24 (256 addresses). Runs parallel pings. timeout: per-host wait in seconds. Returns list of alive IPs."""
    if not network or not network.strip():
        return {"error": "network must not be empty", "tool": "ping_sweep"}
    network = network.strip()
    timeout = min(max(1, timeout), 10)
    try:
        if ":" in network:
            return {"error": "ping_sweep only supports IPv4 CIDR ranges (e.g. '192.168.1.0/24'). IPv6 is not supported.", "tool": "ping_sweep"}
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
        return {"error": str(e), "tool": "check_sip", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "check_mongodb", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "check_vnc", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "check_postgres", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_redis(host: str, port: int = 6379, timeout: int = 5, password: str = "") -> dict:
    """Connect to a Redis server, send PING, and verify the PONG response. Optionally authenticate with AUTH before pinging. Returns whether the server is reachable, the Redis server version (from INFO server), and response time. password: optional Redis AUTH password (empty = no auth). port: 6379 (default) or custom."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_redis"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "check_redis"}
    timeout = min(max(1, timeout), 30)
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            f = sock.makefile("rwb", buffering=0)
            if password:
                f.write(f"*2\r\n$4\r\nAUTH\r\n${len(password)}\r\n{password}\r\n".encode())
                f.flush()
                auth_resp = f.readline().decode("utf-8", errors="replace").strip()
                if not auth_resp.startswith("+OK"):
                    return {"result": {"host": host, "port": port, "reachable": True, "authenticated": False, "auth_error": auth_resp}}
            f.write(b"*1\r\n$4\r\nPING\r\n")
            f.flush()
            pong = f.readline().decode("utf-8", errors="replace").strip()
            elapsed_ms = round((time.monotonic() - start) * 1000, 2)
            if not pong.startswith("+PONG"):
                return {"result": {"host": host, "port": port, "reachable": True, "ping_ok": False, "response": pong, "elapsed_ms": elapsed_ms}}
            f.write(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
            f.flush()
            info_lines = []
            header = f.readline().decode("utf-8", errors="replace").strip()
            if header.startswith("$"):
                byte_count = int(header[1:])
                info_data = f.read(byte_count).decode("utf-8", errors="replace")
                info_lines = info_data.splitlines()
        server_version = None
        redis_mode = None
        for line in info_lines:
            if line.startswith("redis_version:"):
                server_version = line.split(":", 1)[1].strip()
            elif line.startswith("redis_mode:"):
                redis_mode = line.split(":", 1)[1].strip()
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "ping_ok": True,
                "server_version": server_version,
                "redis_mode": redis_mode,
                "elapsed_ms": elapsed_ms,
            }
        }
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "connection refused"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "reason": "timeout"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_redis", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "check_memcached", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "check_mqtt", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "check_vault", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "check_zookeeper", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_influxdb(host: str, port: int = 8086, timeout: int = 5, https: bool = False) -> dict:
    """Check InfluxDB server health. Supports both InfluxDB v2 (GET /health → JSON status/pass) and v1 (GET /ping → 204 No Content). Returns version, status, and commit information when available. host: IP or hostname. port: default 8086. https: use HTTPS (default False)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_influxdb"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/health", headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode())
            return {
                "result": {
                    "host": host, "port": port, "reachable": True,
                    "status": data.get("status"),
                    "name": data.get("name"),
                    "message": data.get("message"),
                    "version": data.get("version"),
                    "commit": data.get("commit"),
                }
            }
        except urllib.error.HTTPError:
            pass
        req_ping = urllib.request.Request(f"{scheme}://{host}:{port}/ping")
        with urllib.request.urlopen(req_ping, timeout=timeout, context=ctx) as resp:
            x_influxdb_version = resp.headers.get("X-Influxdb-Version", "")
            return {
                "result": {
                    "host": host, "port": port, "reachable": True,
                    "status": "pass", "version": x_influxdb_version or None, "api": "v1",
                }
            }
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_influxdb", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_rabbitmq(host: str, port: int = 15672, timeout: int = 5, username: str = "guest", password: str = "guest") -> dict:
    """Check RabbitMQ server health via the management plugin API. Returns node name, RabbitMQ version, Erlang version, message counts, and running state. host: IP or hostname. port: default 15672 (management HTTP port — enable with 'rabbitmq-plugins enable rabbitmq_management'). username/password: management credentials (default guest/guest)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_rabbitmq"}
    host = host.strip()
    import base64 as _b64
    creds = _b64.b64encode(f"{username}:{password}".encode()).decode()
    url = f"http://{host}:{port}/api/overview"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json", "Authorization": f"Basic {creds}"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        node = data.get("node", "")
        stats = data.get("object_totals", {})
        q_totals = data.get("queue_totals", {})
        return {
            "result": {
                "host": host,
                "port": port,
                "reachable": True,
                "node": node,
                "rabbitmq_version": data.get("rabbitmq_version"),
                "erlang_version": data.get("erlang_version"),
                "total_connections": stats.get("connections"),
                "total_channels": stats.get("channels"),
                "total_queues": stats.get("queues"),
                "messages_ready": q_totals.get("messages_ready"),
                "messages_unacked": q_totals.get("messages_unacknowledged"),
            }
        }
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"error": "Authentication failed — check username/password", "tool": "check_rabbitmq", "status": 401}
        return {"result": {"host": host, "port": port, "reachable": True, "status_code": e.code, "error": str(e.reason)}}
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_rabbitmq", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_kubernetes_api(host: str, port: int = 6443, timeout: int = 5, https: bool = True) -> dict:
    """Check Kubernetes API server health via the /healthz and /version endpoints. Returns API server liveness, individual health check details, and Kubernetes version. host: IP or hostname. port: default 6443. https: use HTTPS (default True)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_kubernetes_api"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    base = f"{scheme}://{host}:{port}"
    try:
        req_health = urllib.request.Request(f"{base}/healthz?verbose", headers={"Accept": "text/plain"})
        with urllib.request.urlopen(req_health, timeout=timeout, context=ctx) as resp:
            health_text = resp.read().decode()
            overall = "ok" if resp.status == 200 else "unhealthy"
        checks: dict[str, str] = {}
        for line in health_text.splitlines():
            line = line.strip()
            if line.startswith("[+]"):
                checks[line[3:].strip()] = "ok"
            elif line.startswith("[-]"):
                checks[line[3:].strip()] = "fail"
        version_data: dict = {}
        try:
            req_v = urllib.request.Request(f"{base}/version", headers={"Accept": "application/json"})
            with urllib.request.urlopen(req_v, timeout=timeout, context=ctx) as resp:
                version_data = json.loads(resp.read().decode())
        except Exception:
            pass
        return {
            "result": {
                "host": host, "port": port, "reachable": True,
                "healthy": overall == "ok",
                "checks": checks,
                "kubernetes_version": version_data.get("gitVersion"),
                "platform": version_data.get("platform"),
                "go_version": version_data.get("goVersion"),
            }
        }
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_kubernetes_api", "host": host, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "check_elasticsearch", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "check_etcd", "host": host, "port": port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "check_consul", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_docker_api(host: str, port: int = 2375, timeout: int = 5, https: bool = False) -> dict:
    """Check Docker daemon REST API availability via GET /_ping. Port 2375 = unencrypted, 2376 = TLS. Returns daemon version info from the response headers."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_docker_api"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/_ping", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode().strip()
            headers = dict(resp.headers)
        return {"result": {
            "host": host,
            "port": port,
            "reachable": True,
            "response": body,
            "api_version": headers.get("Api-Version") or headers.get("api-version"),
            "docker_version": headers.get("Docker-Experimental") or headers.get("Server"),
        }}
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_docker_api", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def http_post(url: str, body: str = "", content_type: str = "application/json", timeout: int = 10, headers: str = "") -> dict:
    """Send an HTTP POST request with a body and return the status code and response. Useful for testing REST API endpoints. body: raw string (JSON, form data, etc). headers: extra request headers as 'Name: Value' pairs separated by newlines or semicolons (e.g. 'Authorization: Bearer token'). Returns status, response body, and parsed JSON if applicable."""
    if not url or not url.strip():
        return {"error": "url must not be empty", "tool": "http_post"}
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://", "tool": "http_post", "url": url}
    timeout = min(max(1, timeout), 60)
    extra_headers: dict[str, str] = {}
    if headers and headers.strip():
        for raw in re.split(r"[;\n]", headers):
            raw = raw.strip()
            if not raw:
                continue
            if ":" not in raw:
                return {"error": f"Invalid header '{raw}': must be 'Name: Value'", "tool": "http_post"}
            hname, _, hval = raw.partition(":")
            extra_headers[hname.strip()] = hval.strip()
    try:
        data = body.encode("utf-8") if body else b""
        req = urllib.request.Request(url, data=data, method="POST", headers=extra_headers)
        req.add_header("Content-Type", content_type)
        req.add_header("Content-Length", str(len(data)))
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            status = resp.status
        result: dict = {"status": status, "body": resp_body[:2000]}
        try:
            result["json"] = json.loads(resp_body)
        except Exception:
            pass
        return {"result": result}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        return {"error": str(e), "tool": "http_post", "detail": type(e).__name__, "status": e.code, "body": err_body[:500]}
    except Exception as e:
        return {"error": str(e), "tool": "http_post", "url": url, "detail": type(e).__name__}


@mcp.tool()
def check_smb(host: str, port: int = 445, timeout: int = 5) -> dict:
    """Check SMB/CIFS file-sharing service reachability. Sends an SMB2 Negotiate request and verifies the response magic bytes. Port 445 = direct SMB, 139 = NetBIOS over TCP."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_smb"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"port {port} out of range 1-65535", "tool": "check_smb"}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        # Minimal SMB2 Negotiate request (RFC 8581): 4-byte NetBIOS header + SMB2 header + Negotiate body
        smb2_header = struct.pack(
            "<4sHHIHHIQIIQ16s",
            b"\xfeSMB",   # ProtocolId
            64,            # StructureSize
            0,             # CreditCharge
            0,             # Status
            0,             # Command: Negotiate
            0x1F,          # CreditResponse
            0,             # Flags
            0,             # NextCommand
            0,             # MessageId
            0,             # Reserved
            0xFFFFFFFF,    # TreeId
            0,             # SessionId
            b"\x00" * 16,  # Signature
        )
        negotiate_body = struct.pack(
            "<HHHHiQHH",
            36,            # StructureSize
            2,             # DialectCount
            1,             # SecurityMode
            0,             # Reserved
            0x7F,          # Capabilities
            0,             # ClientGuid (8 of 16 bytes; rest below)
            0,             # NegotiateContextOffset
            0,             # NegotiateContextCount
            0,             # Reserved2
        ) + b"\x00" * 8 + struct.pack("<HH", 0x0202, 0x0210)  # Guid tail + dialects
        netbios_len = len(smb2_header) + len(negotiate_body)
        packet = struct.pack(">I", netbios_len) + smb2_header + negotiate_body
        sock.sendall(packet)
        response = sock.recv(256)
        sock.close()
        if len(response) >= 8 and b"\xfeSMB" in response:
            return {"result": {"host": host, "port": port, "reachable": True, "protocol": "SMB2"}}
        return {"result": {"host": host, "port": port, "reachable": True, "protocol": "unknown", "note": "TCP connected but SMB2 magic not in response"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "error": "timeout"}}
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "error": "connection refused"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_smb", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_prometheus(host: str, port: int = 9090, timeout: int = 5, https: bool = False) -> dict:
    """Check Prometheus monitoring service health. Queries /-/healthy and /-/ready endpoints and returns status. Also fetches basic TSDB stats from /api/v1/status/tsdb if healthy."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_prometheus"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"port {port} out of range 1-65535", "tool": "check_prometheus"}
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        healthy = False
        ready = False
        for endpoint in ["/-/healthy", "/-/ready"]:
            try:
                req = urllib.request.Request(f"{scheme}://{host}:{port}{endpoint}")
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    if endpoint == "/-/healthy":
                        healthy = resp.status == 200
                    else:
                        ready = resp.status == 200
            except Exception:
                pass
        stats: dict = {}
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v1/status/tsdb", headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                tsdb = json.loads(resp.read().decode())
                stats = tsdb.get("data", {}).get("headStats", {})
        except Exception:
            pass
        return {"result": {"host": host, "port": port, "reachable": healthy or ready, "healthy": healthy, "ready": ready, "tsdb_stats": stats}}
    except Exception as e:
        return {"error": str(e), "tool": "check_prometheus", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_grafana(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Grafana observability platform health via GET /api/health. Returns version, commit hash, database status, and memory usage."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_grafana"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"port {port} out of range 1-65535", "tool": "check_grafana"}
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
        return {"result": {
            "host": host,
            "port": port,
            "reachable": True,
            "version": data.get("version"),
            "commit": data.get("commit"),
            "database": data.get("database"),
            "db_healthy": data.get("database") == "ok",
        }}
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_grafana", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_nfs(host: str, portmapper_port: int = 111, nfs_port: int = 2049, timeout: int = 5) -> dict:
    """Check NFS file server availability. Verifies TCP connectivity on both the portmapper (111) and NFS (2049) ports. Both ports must be reachable for NFS mounts to work."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_nfs"}
    host = host.strip()
    results = {}
    for label, port in [("portmapper", portmapper_port), ("nfs", nfs_port)]:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            results[label] = {"port": port, "reachable": True}
        except socket.timeout:
            results[label] = {"port": port, "reachable": False, "error": "timeout"}
        except ConnectionRefusedError:
            results[label] = {"port": port, "reachable": False, "error": "connection refused"}
        except Exception as e:
            results[label] = {"port": port, "reachable": False, "error": str(e)}
    reachable = all(v["reachable"] for v in results.values())
    return {"result": {"host": host, "reachable": reachable, "ports": results}}


@mcp.tool()
def check_kafka(host: str, port: int = 9092, timeout: int = 5) -> dict:
    """Check Apache Kafka broker availability. Sends a minimal API Versions request (Kafka protocol v0) and verifies a valid Kafka response frame is returned."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_kafka"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"port {port} out of range 1-65535", "tool": "check_kafka"}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        # Kafka ApiVersions request v0: length(4) + api_key(2) + api_version(2) + correlation_id(4) + client_id_length(2=-1 null)
        request_body = struct.pack(">hhih", 18, 0, 0, 1, -1)
        sock.sendall(request_body)
        header = sock.recv(4)
        if len(header) == 4:
            resp_len = struct.unpack(">I", header)[0]
            sock.recv(min(resp_len, 256))
            sock.close()
            return {"result": {"host": host, "port": port, "reachable": True, "protocol": "Kafka"}}
        sock.close()
        return {"result": {"host": host, "port": port, "reachable": True, "protocol": "unknown", "note": "TCP connected but response too short"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "error": "timeout"}}
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "error": "connection refused"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_kafka", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_couchdb(host: str, port: int = 5984, timeout: int = 5, https: bool = False) -> dict:
    """Check Apache CouchDB availability via GET / which returns version and node name. Port 5984 = HTTP, 6984 = HTTPS."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_couchdb"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
        return {"result": {
            "host": host,
            "port": port,
            "reachable": True,
            "version": data.get("version"),
            "uuid": data.get("uuid"),
            "vendor": data.get("vendor", {}).get("name"),
            "features": data.get("features", []),
        }}
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_couchdb", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_cassandra(host: str, port: int = 9042, timeout: int = 5) -> dict:
    """Check Apache Cassandra availability using the CQL binary protocol. Sends a CQL OPTIONS request and verifies a SUPPORTED response, confirming the Cassandra node is accepting connections."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_cassandra"}
    host = host.strip()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        # CQL binary v3 OPTIONS request: version(1) + flags(1) + stream(2) + opcode(1=OPTIONS) + body_length(4)
        options_req = struct.pack(">BBHBI", 0x03, 0x00, 0x0000, 0x05, 0)
        sock.sendall(options_req)
        header = sock.recv(9)
        sock.close()
        if len(header) >= 5 and header[4] == 0x06:  # opcode 0x06 = SUPPORTED
            return {"result": {"host": host, "port": port, "reachable": True, "protocol": "CQL"}}
        if len(header) >= 5:
            return {"result": {"host": host, "port": port, "reachable": True, "protocol": "unknown", "opcode": header[4]}}
        return {"result": {"host": host, "port": port, "reachable": True, "protocol": "unknown", "note": "no response"}}
    except socket.timeout:
        return {"result": {"host": host, "port": port, "reachable": False, "error": "timeout"}}
    except ConnectionRefusedError:
        return {"result": {"host": host, "port": port, "reachable": False, "error": "connection refused"}}
    except Exception as e:
        return {"error": str(e), "tool": "check_cassandra", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_clickhouse(host: str, port: int = 8123, timeout: int = 5, https: bool = False) -> dict:
    """Check ClickHouse OLAP database availability via HTTP /ping endpoint. Returns 'Ok.' on success. Port 8123 = HTTP interface, 8443 = HTTPS. Also returns version from the response header."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_clickhouse"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/ping")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode().strip()
            version = resp.headers.get("X-ClickHouse-Server-Display-Name") or resp.headers.get("Server", "")
        return {"result": {"host": host, "port": port, "reachable": body == "Ok.", "response": body, "server": version}}
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_clickhouse", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_neo4j(host: str, port: int = 7474, timeout: int = 5, https: bool = False) -> dict:
    """Check Neo4j graph database availability via the HTTP API. GET / returns server version and available endpoints. Port 7474 = HTTP, 7473 = HTTPS, 7687 = Bolt (use port_check for Bolt)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_neo4j"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
        neo4j_version = data.get("neo4j_version") or data.get("data", {}).get("neo4j_version")
        return {"result": {
            "host": host,
            "port": port,
            "reachable": True,
            "version": neo4j_version,
            "edition": data.get("neo4j_edition"),
        }}
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_neo4j", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_minio(host: str, port: int = 9000, timeout: int = 5, https: bool = False) -> dict:
    """Check MinIO object storage availability via GET /minio/health/live (liveness) and /minio/health/ready (readiness). Port 9000 = default, 9001 = console. Returns liveness and readiness status separately."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_minio"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    live = False
    ready = False
    errors: dict = {}
    for endpoint, key in [("/minio/health/live", "live"), ("/minio/health/ready", "ready")]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{endpoint}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if key == "live":
                    live = resp.status == 200
                else:
                    ready = resp.status == 200
        except urllib.error.HTTPError as e:
            errors[key] = f"HTTP {e.code}"
        except Exception as e:
            errors[key] = str(e)
    return {"result": {"host": host, "port": port, "reachable": live, "live": live, "ready": ready, "errors": errors or None}}


@mcp.tool()
def check_traefik(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Traefik reverse proxy health via GET /ping (returns 'OK') and GET /api/version. Port 8080 is the default Traefik dashboard/API port. Returns Traefik version if the API is accessible."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_traefik"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ping_ok = False
    version: str | None = None
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/ping")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            ping_ok = resp.status == 200
    except Exception:
        pass
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/version", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            version = data.get("Version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": ping_ok, "ping_ok": ping_ok, "version": version}}


@mcp.tool()
def http_put(url: str, body: str = "", content_type: str = "application/json", timeout: int = 10, headers: str = "") -> dict:
    """Send an HTTP PUT request with a body. Useful for testing REST APIs that use PUT to create or replace resources. body: raw string (JSON, etc). headers: extra request headers as 'Name: Value' pairs separated by newlines or semicolons (e.g. 'Authorization: Bearer token'). Returns status code, response body, and parsed JSON if applicable."""
    if not url or not url.strip():
        return {"error": "url must not be empty", "tool": "http_put"}
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://", "tool": "http_put", "url": url}
    timeout = min(max(1, timeout), 60)
    extra_headers: dict[str, str] = {}
    if headers and headers.strip():
        for raw in re.split(r"[;\n]", headers):
            raw = raw.strip()
            if not raw:
                continue
            if ":" not in raw:
                return {"error": f"Invalid header '{raw}': must be 'Name: Value'", "tool": "http_put"}
            hname, _, hval = raw.partition(":")
            extra_headers[hname.strip()] = hval.strip()
    try:
        data = body.encode("utf-8") if body else b""
        req = urllib.request.Request(url, data=data, method="PUT", headers=extra_headers)
        req.add_header("Content-Type", content_type)
        req.add_header("Content-Length", str(len(data)))
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            status = resp.status
        result: dict = {"status": status, "body": resp_body[:2000]}
        try:
            result["json"] = json.loads(resp_body)
        except Exception:
            pass
        return {"result": result}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        return {"error": str(e), "tool": "http_put", "detail": type(e).__name__, "status": e.code, "body": err_body[:500]}
    except Exception as e:
        return {"error": str(e), "tool": "http_put", "url": url, "detail": type(e).__name__}


@mcp.tool()
def http_delete(url: str, body: str = "", content_type: str = "application/json", timeout: int = 10, headers: str = "") -> dict:
    """Send an HTTP DELETE request. Some REST APIs require a body with DELETE (e.g. bulk delete). body: optional request body. headers: extra request headers as 'Name: Value' pairs separated by newlines or semicolons. Returns status code and response body."""
    if not url or not url.strip():
        return {"error": "url must not be empty", "tool": "http_delete"}
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://", "tool": "http_delete", "url": url}
    timeout = min(max(1, timeout), 60)
    extra_headers: dict[str, str] = {}
    if headers and headers.strip():
        for raw in re.split(r"[;\n]", headers):
            raw = raw.strip()
            if not raw:
                continue
            if ":" not in raw:
                return {"error": f"Invalid header '{raw}': must be 'Name: Value'", "tool": "http_delete"}
            hname, _, hval = raw.partition(":")
            extra_headers[hname.strip()] = hval.strip()
    try:
        data = body.encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, method="DELETE", headers=extra_headers)
        if data:
            req.add_header("Content-Type", content_type)
            req.add_header("Content-Length", str(len(data)))
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            status = resp.status
        result: dict = {"status": status, "body": resp_body[:2000]}
        try:
            result["json"] = json.loads(resp_body)
        except Exception:
            pass
        return {"result": result}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        return {"error": str(e), "tool": "http_delete", "detail": type(e).__name__, "status": e.code, "body": err_body[:500]}
    except Exception as e:
        return {"error": str(e), "tool": "http_delete", "url": url, "detail": type(e).__name__}


@mcp.tool()
def http_patch(url: str, body: str = "", content_type: str = "application/json", timeout: int = 10, headers: str = "") -> dict:
    """Send an HTTP PATCH request with a body. Use for partial resource updates in REST APIs (unlike PUT which replaces the whole resource). body: raw string (JSON patch, merge patch, etc). headers: extra request headers as 'Name: Value' pairs separated by newlines or semicolons. Returns status code, response body, and parsed JSON if applicable."""
    if not url or not url.strip():
        return {"error": "url must not be empty", "tool": "http_patch"}
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://", "tool": "http_patch", "url": url}
    timeout = min(max(1, timeout), 60)
    extra_headers: dict[str, str] = {}
    if headers and headers.strip():
        for raw in re.split(r"[;\n]", headers):
            raw = raw.strip()
            if not raw:
                continue
            if ":" not in raw:
                return {"error": f"Invalid header '{raw}': must be 'Name: Value'", "tool": "http_patch"}
            hname, _, hval = raw.partition(":")
            extra_headers[hname.strip()] = hval.strip()
    try:
        data = body.encode("utf-8") if body else b""
        req = urllib.request.Request(url, data=data, method="PATCH", headers=extra_headers)
        req.add_header("Content-Type", content_type)
        req.add_header("Content-Length", str(len(data)))
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            status = resp.status
        result: dict = {"status": status, "body": resp_body[:2000]}
        try:
            result["json"] = json.loads(resp_body)
        except Exception:
            pass
        return {"result": result}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        return {"error": str(e), "tool": "http_patch", "detail": type(e).__name__, "status": e.code, "body": err_body[:500]}
    except Exception as e:
        return {"error": str(e), "tool": "http_patch", "url": url, "detail": type(e).__name__}


@mcp.tool()
def check_opensearch(host: str, port: int = 9200, timeout: int = 5, https: bool = False) -> dict:
    """Check OpenSearch (or Elasticsearch-compatible) cluster health via GET /_cluster/health. Returns cluster name, status (green/yellow/red), node counts, and shard stats. Port 9200 = default HTTP, 9300 = transport."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_opensearch"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/_cluster/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
        return {"result": {
            "host": host,
            "port": port,
            "reachable": True,
            "cluster": data.get("cluster_name"),
            "status": data.get("status"),
            "nodes": data.get("number_of_nodes"),
            "data_nodes": data.get("number_of_data_nodes"),
            "active_shards": data.get("active_shards"),
            "unassigned_shards": data.get("unassigned_shards"),
            "healthy": data.get("status") == "green",
        }}
    except urllib.error.URLError as e:
        return {"result": {"host": host, "port": port, "reachable": False, "error": str(e.reason)}}
    except Exception as e:
        return {"error": str(e), "tool": "check_opensearch", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_loki(host: str, port: int = 3100, timeout: int = 5, https: bool = False) -> dict:
    """Check Grafana Loki log aggregation service via GET /ready and /loki/api/v1/status/buildinfo. Returns readiness status and build version."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_loki"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ready = False
    version: str | None = None
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/ready")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            ready = resp.status == 200
    except Exception:
        pass
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/loki/api/v1/status/buildinfo", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": ready, "ready": ready, "version": version}}


@mcp.tool()
def check_alertmanager(host: str, port: int = 9093, timeout: int = 5, https: bool = False) -> dict:
    """Check Prometheus Alertmanager health via GET /-/healthy and /-/ready. Returns health/readiness status and version from the API."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_alertmanager"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    ready = False
    version: str | None = None
    for endpoint, key in [("/-/healthy", "healthy"), ("/-/ready", "ready")]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{endpoint}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if key == "healthy":
                    healthy = resp.status == 200
                else:
                    ready = resp.status == 200
        except Exception:
            pass
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v2/status", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            version = data.get("versionInfo", {}).get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy or ready, "healthy": healthy, "ready": ready, "version": version}}


@mcp.tool()
def check_tempo(host: str, port: int = 3200, timeout: int = 5, https: bool = False) -> dict:
    """Check Grafana Tempo distributed tracing service via GET /ready and /api/echo. Returns readiness status and whether the API is responding. port: 3200 (default HTTP), 9095 (gRPC — use port_check for gRPC)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_tempo"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "check_tempo"}
    timeout = min(max(1, timeout), 30)
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ready = False
    api_ok = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/ready")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            ready = resp.status == 200
    except Exception:
        pass
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/echo")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            api_ok = resp.status == 200
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": ready or api_ok, "ready": ready, "api_ok": api_ok}}


@mcp.tool()
def check_jaeger(host: str, port: int = 16686, timeout: int = 5, https: bool = False) -> dict:
    """Check Jaeger distributed tracing UI and query API via GET / (UI) and /api/services. Returns whether the UI is reachable and whether the query API is responding with valid JSON. port: 16686 (default UI/query). For Jaeger collector, use port_check on port 14268 (HTTP) or 6831 (UDP)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_jaeger"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "check_jaeger"}
    timeout = min(max(1, timeout), 30)
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ui_ok = False
    api_ok = False
    services: list | None = None
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            ui_ok = resp.status == 200
    except Exception:
        pass
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/services", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            api_ok = True
            services = data.get("data", [])
    except Exception:
        pass
    return {
        "result": {
            "host": host,
            "port": port,
            "reachable": ui_ok or api_ok,
            "ui_ok": ui_ok,
            "api_ok": api_ok,
            "services": services,
        }
    }


@mcp.tool()
def check_uptime_kuma(host: str, port: int = 3001, timeout: int = 5, https: bool = False) -> dict:
    """Check Uptime Kuma monitoring service health via GET /api/health. Returns health status and version if available."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_uptime_kuma"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/health",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_vaultwarden(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Vaultwarden (Bitwarden-compatible) password manager health via GET /alive. Returns health status."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_vaultwarden"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/alive")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_syncthing(host: str, port: int = 8384, timeout: int = 5, https: bool = False, api_key: str = "") -> dict:
    """Check Syncthing file sync service health via GET /rest/noauth/health. Returns status and version. api_key: optional Syncthing API key for authenticated endpoints."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_syncthing"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/rest/noauth/health",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            healthy = data.get("status") == "OK"
    except Exception:
        pass
    if api_key:
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}/rest/system/version",
                headers={"X-API-Key": api_key, "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode())
                version = data.get("version")
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_gitea(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Gitea/Forgejo git server health via GET /api/healthz. Returns status and availability."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_gitea"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/healthz",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            healthy = data.get("status") == "pass"
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_nextcloud(host: str, port: int = 443, timeout: int = 5, https: bool = True) -> dict:
    """Check Nextcloud/ownCloud instance health via GET /status.php. Returns installed, maintenance mode, and version."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_nextcloud"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    installed = False
    maintenance = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/status.php",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            installed = bool(data.get("installed"))
            maintenance = bool(data.get("maintenance"))
            version = data.get("versionstring") or data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": installed, "installed": installed, "maintenance": maintenance, "version": version}}


@mcp.tool()
def check_jellyfin(host: str, port: int = 8096, timeout: int = 5, https: bool = False) -> dict:
    """Check Jellyfin media server health via GET /health. Returns health status and version from public system info."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_jellyfin"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/health")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
    except Exception:
        pass
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/System/Info/Public",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            version = data.get("Version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_immich(host: str, port: int = 2283, timeout: int = 5, https: bool = False) -> dict:
    """Check Immich photo management server health via GET /api/server-info/ping. Returns ping response."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_immich"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/server-info/ping",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            healthy = data.get("res") == "pong"
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_portainer(host: str, port: int = 9443, timeout: int = 5, https: bool = True) -> dict:
    """Check Portainer container management UI health via GET /api/status. Returns version and instance ID."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_portainer"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/status",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("Version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_homeassistant(host: str, port: int = 8123, timeout: int = 5, https: bool = False, token: str = "") -> dict:
    """Check Home Assistant health via GET /api/. Returns running state and version. token: optional long-lived access token for authenticated response (otherwise returns 401 which still confirms HA is running)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_homeassistant"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    reachable = False
    version: str | None = None
    headers: dict = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token.strip()}"
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/", headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except urllib.error.HTTPError as e:
        reachable = e.code in (401, 403)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": reachable, "version": version}}


@mcp.tool()
def check_authentik(host: str, port: int = 9000, timeout: int = 5, https: bool = False) -> dict:
    """Check Authentik identity provider health via GET /-/health/live/ and /-/health/ready/. Returns live and ready states."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_authentik"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    live = False
    ready = False
    for endpoint, key in [("/-/health/live/", "live"), ("/-/health/ready/", "ready")]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{endpoint}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if key == "live":
                    live = resp.status == 200
                else:
                    ready = resp.status == 200
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": live, "live": live, "ready": ready}}


@mcp.tool()
def check_adguard(host: str, port: int = 3000, timeout: int = 5, https: bool = False, username: str = "", password: str = "") -> dict:
    """Check AdGuard Home DNS filter health via GET /control/status. Returns running state and version. username/password: optional Basic auth credentials."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_adguard"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/control/status",
            headers={"Accept": "application/json"},
        )
        if username and password:
            import base64
            creds = base64.b64encode(f"{username}:{password}".encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_paperless(host: str, port: int = 8000, timeout: int = 5, https: bool = False) -> dict:
    """Check Paperless-NGX document management health. Attempts GET /api/ (returns 401 without auth, confirming service is running). Returns reachable state."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_paperless"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    reachable = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 403)
    except urllib.error.HTTPError as e:
        reachable = e.code in (401, 403)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": reachable}}


@mcp.tool()
def check_miniflux(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Miniflux RSS reader health via GET /healthcheck. Returns healthy state."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_miniflux"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/healthcheck")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode().strip()
            healthy = resp.status == 200 and body == "OK"
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_mealie(host: str, port: int = 9000, timeout: int = 5, https: bool = False) -> dict:
    """Check Mealie recipe manager health via GET /api/about. Returns version and build info."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_mealie"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/about",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_keycloak(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Keycloak identity server health via GET /health/live and /health/ready (Keycloak 20+). Falls back to /auth/health for older versions. Returns live and ready states."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_keycloak"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    live = False
    ready = False
    for path in ["/health/live", "/auth/health/live"]:
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}{path}",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode())
                live = data.get("status") == "UP"
                break
        except Exception:
            pass
    for path in ["/health/ready", "/auth/health/ready"]:
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}{path}",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode())
                ready = data.get("status") == "UP"
                break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": live, "live": live, "ready": ready}}


@mcp.tool()
def check_ntfy(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check ntfy push notification server health via GET /v1/health. Returns healthy state and version."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_ntfy"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/v1/health",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            healthy = bool(data.get("healthy"))
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_gotify(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Gotify push notification server health via GET /health. Returns healthy state and version."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_gotify"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/health",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version") or data.get("info", {}).get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_searxng(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check SearXNG meta-search engine availability via GET /healthz. Falls back to checking the homepage returns 200."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_searxng"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/healthz", "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status == 200
                break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_freshrss(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check FreshRSS feed aggregator availability. FreshRSS has no dedicated health endpoint; checks if the main page or /i/ returns HTTP 200."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_freshrss"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/i/", "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status == 200
                break
        except urllib.error.HTTPError as e:
            healthy = e.code in (200, 302, 301)
            if healthy:
                break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_bookstack(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check BookStack wiki platform health via GET /status. Returns health status."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_bookstack"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/status",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_monica(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Monica personal CRM availability. Monica has no dedicated health endpoint; checks if the main page returns HTTP 200 or redirect."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_monica"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status in (200, 302, 301)
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 302, 301)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_vikunja(host: str, port: int = 3456, timeout: int = 5, https: bool = False) -> dict:
    """Check Vikunja task manager health via GET /api/v1/info. Returns version and build information."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_vikunja"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v1/info",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_stirling_pdf(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Stirling-PDF tools server health via GET /api/v1/info. Returns healthy state and version."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_stirling_pdf"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    for path in ["/api/v1/info", "/actuator/health"]:
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}{path}",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status == 200
                data = json.loads(resp.read().decode())
                version = data.get("version") or (data.get("status") == "UP" and "UP") or None
                if healthy:
                    break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_grocy(host: str, port: int = 9283, timeout: int = 5, https: bool = False) -> dict:
    """Check Grocy grocery and household management server via GET /api/system/info. Returns version and PHP info."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_grocy"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/system/info",
            headers={"Accept": "application/json", "GROCY-API-KEY": "demo_mode"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("grocy_version")
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 401, 403)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_actual_budget(host: str, port: int = 5006, timeout: int = 5, https: bool = False) -> dict:
    """Check Actual Budget personal finance server health via GET /health. Returns healthy state."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_actual_budget"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/health")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_linkwarden(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Linkwarden bookmark manager availability via GET /api/v1/auth/session (returns 401 without auth, confirming service is running)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_linkwarden"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    reachable = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v1/auth/session")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 403)
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401, 403)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": reachable}}


@mcp.tool()
def check_photoprism(host: str, port: int = 2342, timeout: int = 5, https: bool = False) -> dict:
    """Check PhotoPrism photo management server health via GET /api/v1/status. Returns running state and version."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_photoprism"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v1/status",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_wallabag(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Wallabag read-it-later service availability. Checks GET /api/info (401 without auth = running) or homepage."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_wallabag"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    reachable = False
    for path in ["/api/info", "/"]:
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}{path}",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                reachable = resp.status in (200, 302)
                break
        except urllib.error.HTTPError as e:
            reachable = e.code in (200, 401, 403, 302)
            if reachable:
                break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": reachable}}


@mcp.tool()
def check_tandoor(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Tandoor recipe manager health via GET /api/schema/ (public OpenAPI schema endpoint). Returns reachable state."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_tandoor"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/api/schema/", "/api/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status == 200
                break
        except urllib.error.HTTPError as e:
            healthy = e.code in (200, 403)
            if healthy:
                break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_outline(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Outline wiki/knowledge base health via GET /api/_healthcheck. Returns healthy state."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_outline"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/api/_healthcheck", "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status == 200
                break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_plausible(host: str, port: int = 8000, timeout: int = 5, https: bool = False) -> dict:
    """Check Plausible Analytics health via GET /api/health. Returns database and clickhouse status."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_plausible"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    postgres_ok = False
    clickhouse_ok = False
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/health",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            postgres_ok = data.get("postgres") == "ok"
            clickhouse_ok = data.get("clickhouse") == "ok"
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "postgres": postgres_ok, "clickhouse": clickhouse_ok}}


@mcp.tool()
def check_mattermost(host: str, port: int = 8065, timeout: int = 5, https: bool = False) -> dict:
    """Check Mattermost team messaging server health via GET /api/v4/system/ping. Returns status and database health."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_mattermost"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v4/system/ping",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            healthy = data.get("status") == "OK"
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_forgejo(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Forgejo (Gitea fork) git server health via GET /api/healthz. Returns status."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_forgejo"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/healthz",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            healthy = data.get("status") == "pass"
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_matrix_synapse(host: str, port: int = 8008, timeout: int = 5, https: bool = False) -> dict:
    """Check Matrix Synapse homeserver health via GET /_matrix/federation/v1/version (public endpoint). Returns server version."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_matrix_synapse"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/_matrix/federation/v1/version",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("server", {}).get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_zipline(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Zipline file sharing server health via GET /api/server/info. Returns version and build info."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_zipline"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/server/info",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_guacamole(host: str, port: int = 8080, timeout: int = 5, https: bool = False, path: str = "/guacamole") -> dict:
    """Check Apache Guacamole clientless remote desktop gateway via GET /guacamole/api/ (returns API version). path: context path if non-default (e.g. '/guacamole')."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_guacamole"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    base = path.rstrip("/") if path else ""
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}{base}/api/",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("_version")
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 403)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_navidrome(host: str, port: int = 4533, timeout: int = 5, https: bool = False) -> dict:
    """Check Navidrome music streaming server health via GET /app/manifest.json (public endpoint). Returns reachable state."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_navidrome"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/app/manifest.json", "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status == 200
                break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_qbittorrent(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check qBittorrent Web UI health via GET /api/v2/app/version. Returns version string. 403 = running but not logged in (still healthy). Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_qbittorrent"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v2/app/version")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            version = resp.read().decode().strip()
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 403)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_prowlarr(host: str, port: int = 9696, timeout: int = 5, https: bool = False) -> dict:
    """Check Prowlarr indexer manager health via GET /api/v1/system/status. Returns version and startup time. Default port 9696."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_prowlarr"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v1/system/status",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 401)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_lidarr(host: str, port: int = 8686, timeout: int = 5, https: bool = False) -> dict:
    """Check Lidarr music collection manager health via GET /api/v1/system/status. Returns version and startup time. Default port 8686."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_lidarr"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v1/system/status",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 401)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_readarr(host: str, port: int = 8787, timeout: int = 5, https: bool = False) -> dict:
    """Check Readarr book/eBook collection manager health via GET /api/v1/system/status. Returns version and startup time. Default port 8787."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_readarr"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v1/system/status",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 401)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_bazarr(host: str, port: int = 6767, timeout: int = 5, https: bool = False) -> dict:
    """Check Bazarr subtitle management server health via GET /api/system/status. Returns version string. 401 = running but API key required (still healthy). Default port 6767."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_bazarr"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/system/status",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("data", {}).get("bazarr_version") if isinstance(data.get("data"), dict) else None
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 401, 403)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_audiobookshelf(host: str, port: int = 13378, timeout: int = 5, https: bool = False) -> dict:
    """Check Audiobookshelf audiobook and podcast server health via GET /api/health. Returns server version. Default port 13378."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_audiobookshelf"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/health",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("serverVersion")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_kavita(host: str, port: int = 5000, timeout: int = 5, https: bool = False) -> dict:
    """Check Kavita manga, comic, and book reader server health via GET /api/health. Default port 5000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_kavita"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/health")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_transmission(host: str, port: int = 9091, timeout: int = 5, https: bool = False) -> dict:
    """Check Transmission BitTorrent client RPC health via GET /transmission/rpc. A 409 response (CSRF token required) confirms Transmission is running. Default port 9091."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_transmission"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/transmission/rpc")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status in (200, 409)
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 401, 403, 409)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_jellyseerr(host: str, port: int = 5055, timeout: int = 5, https: bool = False) -> dict:
    """Check Jellyseerr media request and discovery manager health via GET /api/v1/status. Returns version string. Default port 5055."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_jellyseerr"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v1/status",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_sabnzbd(host: str, port: int = 8080, timeout: int = 5, https: bool = False, path: str = "/sabnzbd") -> dict:
    """Check SABnzbd usenet downloader health via GET /sabnzbd/. 200 or redirect to login page = healthy. path: context path if non-default (e.g. '/sabnzbd'). Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_sabnzbd"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    base = path.strip().rstrip("/") if path else ""
    for check_path in [base + "/", base or "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{check_path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status in (200, 302)
                break
        except urllib.error.HTTPError as e:
            healthy = e.code in (200, 302, 401, 403)
            break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_nzbget(host: str, port: int = 6789, timeout: int = 5, https: bool = False) -> dict:
    """Check NZBGet usenet downloader health via GET /. 200 or 401 (basic auth) = healthy. Default port 6789."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_nzbget"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status in (200, 302)
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 302, 401, 403)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_calibre_web(host: str, port: int = 8083, timeout: int = 5, https: bool = False) -> dict:
    """Check Calibre-Web ebook library server health via GET /. 200 or redirect to /login = healthy. Default port 8083."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_calibre_web"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status in (200, 302)
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 302, 401, 403)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_glances(host: str, port: int = 61208, timeout: int = 5, https: bool = False) -> dict:
    """Check Glances system monitoring server health via GET /api/3/status. Returns version. Default port 61208."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_glances"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/3/status",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_netdata(host: str, port: int = 19999, timeout: int = 5, https: bool = False) -> dict:
    """Check Netdata real-time performance monitoring server health via GET /api/v1/info. Returns version and operating system. Default port 19999."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_netdata"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v1/info",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_cockpit(host: str, port: int = 9090, timeout: int = 5, https: bool = False) -> dict:
    """Check Cockpit Linux server management web UI health. Tries GET /cockpit/login — 200, 302, or 401 = healthy. Default port 9090 (most installs use HTTPS)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_cockpit"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for check_path in ["/cockpit/login", "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{check_path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status in (200, 302)
                break
        except urllib.error.HTTPError as e:
            healthy = e.code in (200, 302, 401, 403)
            break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_changedetection(host: str, port: int = 5000, timeout: int = 5, https: bool = False) -> dict:
    """Check changedetection.io web change monitoring server health via GET /api/v1/systeminfo. Returns version. Default port 5000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_changedetection"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v1/systeminfo",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 401, 403)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_flaresolverr(host: str, port: int = 8191, timeout: int = 5, https: bool = False) -> dict:
    """Check FlareSolverr Cloudflare bypass proxy health via GET /v1. Returns version and number of active sessions. Default port 8191."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_flaresolverr"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    sessions: int | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/v1",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
            sessions = data.get("sessions")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version, "sessions": sessions}}


@mcp.tool()
def check_penpot(host: str, port: int = 9001, timeout: int = 5, https: bool = False) -> dict:
    """Check Penpot open-source design tool health via GET /api/rpc/command/get-profile. 401 = running (auth required). Default port 9001."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_penpot"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/rpc/command/get-profile")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status in (200, 401, 403)
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 401, 403)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_joplin_server(host: str, port: int = 22300, timeout: int = 5, https: bool = False) -> dict:
    """Check Joplin Server note-syncing backend health via GET /api/ping. Returns status 'ok'. Default port 22300."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_joplin_server"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    status: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/ping",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            status = data.get("status")
            healthy = healthy and status == "ok"
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "status": status}}


@mcp.tool()
def check_nocodb(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check NocoDB no-code database platform health via GET /api/v1/health. Returns status 'ok'. Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_nocodb"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v1/health",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            healthy = data.get("message") == "OK" or data.get("status") == "ok" or healthy
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 302)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_hoppscotch(host: str, port: int = 3170, timeout: int = 5, https: bool = False) -> dict:
    """Check Hoppscotch self-hosted API testing platform backend health via GET /api/health or root path. Default backend port 3170 (frontend is 3000)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_hoppscotch"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/api/health", "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status in (200, 302)
                break
        except urllib.error.HTTPError as e:
            healthy = e.code in (200, 302, 401, 403)
            break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_n8n(host: str, port: int = 5678, timeout: int = 5, https: bool = False) -> dict:
    """Check n8n workflow automation platform health via GET /healthz. Returns status 'ok'. Default port 5678."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_n8n"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/healthz",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_directus(host: str, port: int = 8055, timeout: int = 5, https: bool = False) -> dict:
    """Check Directus headless CMS health via GET /server/health. Returns status 'ok' and service checks. Default port 8055."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_directus"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    status: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/server/health",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            status = data.get("status")
            healthy = healthy and status == "ok"
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "status": status}}


@mcp.tool()
def check_appwrite(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Appwrite open-source BaaS health via GET /v1/health. Returns HTTP status. Default port 80 (HTTPS on 443)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_appwrite"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/v1/health",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 401)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_windmill(host: str, port: int = 8000, timeout: int = 5, https: bool = False) -> dict:
    """Check Windmill workflow automation platform health via GET /api/version. Returns version string. Default port 8000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_windmill"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/version")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            version = resp.read().decode().strip()
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_umami(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Umami privacy-focused analytics server health via GET /api/heartbeat. Returns 'OK' text response. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_umami"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/heartbeat")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_planka(host: str, port: int = 1337, timeout: int = 5, https: bool = False) -> dict:
    """Check Planka kanban project management board health via GET /api/health or root path. 200 or 401 = healthy. Default port 1337."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_planka"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/api/health", "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status in (200, 302)
                break
        except urllib.error.HTTPError as e:
            healthy = e.code in (200, 302, 401, 403)
            break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_kimai(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Kimai time-tracking application health via GET /api/version. Returns version string. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_kimai"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/version",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 401, 403)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_snipe_it(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Snipe-IT IT asset management application health via GET /api/v1/settings/general (401 without token = running). Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_snipe_it"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/api/v1/settings/general", "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status in (200, 302)
                break
        except urllib.error.HTTPError as e:
            healthy = e.code in (200, 302, 401, 403)
            break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_code_server(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check code-server (VSCode in browser) health via GET /healthz. Returns 'OK'. Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_code_server"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/healthz")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_filebrowser(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check File Browser web-based file manager health via GET /api/health. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_filebrowser"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/api/health", "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status in (200, 302)
                break
        except urllib.error.HTTPError as e:
            healthy = e.code in (200, 302, 401, 403)
            break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_memos(host: str, port: int = 5230, timeout: int = 5, https: bool = False) -> dict:
    """Check Memos self-hosted lightweight notes server health via GET /api/v1/workspace/profile. Returns version. Default port 5230."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_memos"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v1/workspace/profile",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_rallly(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Rallly open-source scheduling and polls application health via GET /api/health or root. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_rallly"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/api/health", "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status in (200, 302)
                break
        except urllib.error.HTTPError as e:
            healthy = e.code in (200, 302, 401, 403)
            break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_seafile(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Seafile file sync and share server health via GET /api2/ping/. Returns 'pong' on success. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_seafile"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api2/ping/")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200 and b"pong" in resp.read()
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_onlyoffice(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check OnlyOffice Document Server health via GET /healthcheck. Returns 'true' on success. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_onlyoffice"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/healthcheck")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            body = resp.read().decode().strip().lower()
            healthy = healthy and body == "true"
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_hedgedoc(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check HedgeDoc collaborative markdown notes server health via GET /api/v2/status. Returns version and connection count. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_hedgedoc"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v2/status",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            version = data.get("version")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_collabora(host: str, port: int = 9980, timeout: int = 5, https: bool = False) -> dict:
    """Check Collabora Online Office server health via GET /api/v1/config. 200 or 400 = server running. Default port 9980."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_collabora"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/api/v1/config", "/lool/convert-to/", "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status in (200, 302, 400)
                break
        except urllib.error.HTTPError as e:
            healthy = e.code in (200, 302, 400, 401, 403)
            break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_wordpress(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check WordPress site health via GET /wp-json/. Returns site name and description. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_wordpress"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    site_name: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/wp-json/",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
            site_name = data.get("name")
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "site_name": site_name}}


@mcp.tool()
def check_ghost(host: str, port: int = 2368, timeout: int = 5, https: bool = False) -> dict:
    """Check Ghost blog platform health via GET /ghost/api/admin/site/. Returns version and site title. Default port 2368."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_ghost"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    title: str | None = None
    for path in ["/ghost/api/admin/site/", "/ghost/api/v4/admin/site/"]:
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}{path}",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    healthy = True
                    data = json.loads(resp.read().decode())
                    site = data.get("site", {})
                    version = site.get("version")
                    title = site.get("title")
                    break
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                healthy = True
                break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version, "title": title}}


@mcp.tool()
def http_security_headers(host: str, port: int = 80, timeout: int = 5, https: bool = False, path: str = "/") -> dict:
    """Audit HTTP security headers on a web server. Checks for: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and X-XSS-Protection. Returns which are present with their values, which are missing, and a score."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "http_security_headers"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"port must be 1-65535, got {port}", "tool": "http_security_headers"}
    timeout = min(max(1, timeout), 30)
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    security_header_names = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-XSS-Protection",
    ]
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            present = {}
            missing = []
            for h in security_header_names:
                val = headers_lower.get(h.lower())
                if val:
                    present[h] = val
                else:
                    missing.append(h)
            return {"result": {
                "host": host,
                "port": port,
                "reachable": True,
                "status": resp.status,
                "present": present,
                "missing": missing,
                "score": f"{len(present)}/{len(security_header_names)}",
            }}
    except urllib.error.HTTPError as e:
        headers_lower = {k.lower(): v for k, v in e.headers.items()}
        present = {}
        missing = []
        for h in security_header_names:
            val = headers_lower.get(h.lower())
            if val:
                present[h] = val
            else:
                missing.append(h)
        return {"result": {
            "host": host,
            "port": port,
            "reachable": True,
            "status": e.code,
            "present": present,
            "missing": missing,
            "score": f"{len(present)}/{len(security_header_names)}",
        }}
    except Exception as e:
        return {"error": str(e), "tool": "http_security_headers", "host": host, "port": port, "detail": type(e).__name__}


@mcp.tool()
def check_gitlab(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check GitLab instance health via GET /-/health. Confirms the application is running and can accept requests. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_gitlab"}
    host = host.strip()
    if not 1 <= port <= 65535:
        return {"error": f"port must be 1-65535, got {port}", "tool": "check_gitlab"}
    timeout = min(max(1, timeout), 30)
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/-/health")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode().strip()
            healthy = resp.status == 200 and "GitLab" in body
    except Exception:
        pass
    if not healthy:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}/-/liveness")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status == 200
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_discourse(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Discourse forum health via GET /srv/status (returns JSON status) or /about.json for version info. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_discourse"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/srv/status")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                healthy = data.get("status") == "ok"
    except Exception:
        pass
    if not healthy:
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}/about.json",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    healthy = True
                    data = json.loads(resp.read().decode())
                    version = data.get("about", {}).get("version")
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_matomo(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Matomo web analytics health via the API ping endpoint. Returns version if the API responds. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_matomo"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    for path in [
        "/matomo.php?module=API&method=API.getMatomoVersion&format=json",
        "/index.php?module=API&method=API.getMatomoVersion&format=JSON",
    ]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    healthy = True
                    body = resp.read().decode()
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            version = data.get("value")
                    except Exception:
                        pass
                    break
        except urllib.error.HTTPError as e:
            if e.code in (301, 302):
                healthy = True
                break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_dokuwiki(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check DokuWiki health via GET /doku.php. A 200 or redirect response confirms the wiki is running. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_dokuwiki"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/doku.php")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status in (200, 301, 302)
    except urllib.error.HTTPError as e:
        healthy = e.code in (200, 301, 302)
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_invoiceninja(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Invoice Ninja health via GET /api/v1/ping. Returns version if the API responds. A 401/403 response also indicates the server is running. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_invoiceninja"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/v1/ping",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status == 200:
                healthy = True
                data = json.loads(resp.read().decode())
                version = data.get("version") or data.get("app_version")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403, 422):
            healthy = True
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_wikijs(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Wiki.js health via GET /healthcheck. Returns healthy status. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_wikijs"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/healthcheck",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status == 200:
                body = resp.read().decode()
                try:
                    data = json.loads(body)
                    healthy = data.get("status") == "ok" or data.get("healthy") is True
                except Exception:
                    healthy = True
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_limesurvey(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check LimeSurvey survey platform health via GET /index.php. A 200 or redirect response confirms the service is running. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_limesurvey"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/index.php", "/"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status in (200, 301, 302)
                break
        except urllib.error.HTTPError as e:
            if e.code in (200, 301, 302):
                healthy = True
                break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_bitwarden(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Bitwarden (Unified) server health via GET /api/alive. A 200 response confirms the server is operational. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_bitwarden"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/alive")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            healthy = True
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_ollama(host: str, port: int = 11434, timeout: int = 5, https: bool = False) -> dict:
    """Check Ollama LLM server health via GET /api/version. Returns version string. Default port 11434."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_ollama"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    version: str | None = None
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/version",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status == 200:
                healthy = True
                data = json.loads(resp.read().decode())
                version = data.get("version")
    except Exception:
        pass
    if not healthy:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}/")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                healthy = resp.status == 200 and b"Ollama" in resp.read()
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy, "version": version}}


@mcp.tool()
def check_open_webui(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Open WebUI (Ollama/LLM frontend) health via GET /health. Returns healthy status. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_open_webui"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/health",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status == 200:
                body = resp.read().decode()
                try:
                    data = json.loads(body)
                    healthy = data.get("status") is True or data.get("status") == "ok" or data.get("healthy") is True
                except Exception:
                    healthy = True
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_pocketbase(host: str, port: int = 8090, timeout: int = 5, https: bool = False) -> dict:
    """Check PocketBase backend health via GET /api/health. Returns healthy status. Default port 8090."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_pocketbase"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/api/health",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                healthy = data.get("code") == 200 or data.get("message", "").lower().find("healthy") >= 0
    except Exception:
        pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_anythingllm(host: str, port: int = 3001, timeout: int = 5, https: bool = False) -> dict:
    """Check AnythingLLM (self-hosted RAG/AI workspace) health via GET /api/ping. Returns healthy status. Default port 3001."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_anythingllm"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/api/ping", "/api/v1/ping"]:
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}{path}",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    healthy = True
                    break
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                healthy = True
                break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "reachable": healthy, "healthy": healthy}}


@mcp.tool()
def check_pihole(host: str, port: int = 80, timeout: int = 5, https: bool = False, api_token: str = "") -> dict:
    """Check Pi-hole DNS ad blocker status via the admin API. Returns enabled, blocking status, DNS queries today, and ads blocked. api_token: Pi-hole API token from Settings > API/Web interface (optional — some stats available without auth). Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_pihole"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    url = f"{scheme}://{host}:{port}/admin/api.php?summary"
    if api_token:
        url += f"&auth={api_token}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}", "tool": "check_pihole", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "check_pihole", "host": host}
    if not data or not isinstance(data, dict):
        return {"error": "Unexpected response from Pi-hole API", "tool": "check_pihole", "host": host}
    return {"result": {
        "host": host,
        "port": port,
        "reachable": True,
        "status": data.get("status", "unknown"),
        "blocking": data.get("status") == "enabled",
        "dns_queries_today": data.get("dns_queries_today"),
        "ads_blocked_today": data.get("ads_blocked_today"),
        "ads_percentage_today": data.get("ads_percentage_today"),
        "unique_domains": data.get("unique_domains"),
        "gravity_last_updated": data.get("gravity_last_updated", {}).get("relative", {}).get("human_readable"),
    }}


@mcp.tool()
def check_frigate(host: str, port: int = 5000, timeout: int = 5, https: bool = False) -> dict:
    """Check Frigate NVR (network video recorder) health via GET /api/stats. Returns camera count, detection FPS, process load, and detector (GPU/CPU) stats. Default port 5000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_frigate"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/stats", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}", "tool": "check_frigate", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "check_frigate", "host": host}
    cameras = data.get("cameras", {})
    detectors = data.get("detectors", {})
    detector_info = {name: {"inference_speed": d.get("inference_speed"), "detection_start": d.get("detection_start")} for name, d in detectors.items()}
    return {"result": {
        "host": host,
        "port": port,
        "healthy": healthy,
        "camera_count": len(cameras),
        "cameras": list(cameras.keys()),
        "detectors": detector_info,
        "service": data.get("service", {}),
    }}


@mcp.tool()
def check_homepage(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Homepage dashboard (gethomepage.dev) health via GET /api/healthcheck. Returns healthy status. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_homepage"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    healthy = False
    for path in ["/api/healthcheck", "/", ""]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port}{path}", headers={"Accept": "application/json, text/html"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    healthy = True
                    break
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                healthy = True
                break
        except Exception:
            pass
    return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": healthy}}


@mcp.tool()
def check_dashdot(host: str, port: int = 3001, timeout: int = 5, https: bool = False) -> dict:
    """Check Dashdot server stats dashboard health via GET /health. Returns healthy status and server info if available. Default port 3001."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_dashdot"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            try:
                data = json.loads(resp.read().decode())
            except Exception:
                data = {}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Some dashdot versions don't have /health — try root
            try:
                req2 = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
                with urllib.request.urlopen(req2, timeout=timeout, context=ctx) as resp2:
                    return {"result": {"host": host, "port": port, "healthy": resp2.status == 200, "reachable": resp2.status == 200}}
            except Exception as e2:
                return {"error": str(e2), "tool": "check_dashdot", "host": host}
        return {"error": f"HTTP {e.code}: {e.reason}", "tool": "check_dashdot", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "check_dashdot", "host": host}
    return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": healthy, "info": data}}


@mcp.tool()
def check_victoriametrics(host: str, port: int = 8428, timeout: int = 5, https: bool = False) -> dict:
    """Check VictoriaMetrics (time-series database) health via GET /health and retrieve /api/v1/status/tsdb summary. Returns healthy, version if available, and time series count. Default port 8428. Set https=True for HTTPS."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_victoriametrics"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/health", headers={"Accept": "text/plain"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            body = resp.read().decode("utf-8", errors="replace").strip()
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}", "tool": "check_victoriametrics", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "check_victoriametrics", "host": host}
    result: dict = {"host": host, "port": port, "healthy": healthy, "status": body}
    try:
        req2 = urllib.request.Request(f"{scheme}://{host}:{port}/api/v1/status/tsdb", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req2, timeout=timeout, context=ctx) as resp2:
            data = json.loads(resp2.read().decode())
            stats = data.get("data", {})
            result["series_count"] = stats.get("totalSeries")
            result["label_value_count"] = stats.get("totalLabelValuePairs")
    except Exception:
        pass
    return {"result": result}


@mcp.tool()
def check_zipkin(host: str, port: int = 9411, timeout: int = 5, https: bool = False) -> dict:
    """Check Zipkin (distributed tracing) health via GET /health and retrieve service count from /api/v2/services. Returns healthy, status, and service names. Default port 9411. Set https=True for HTTPS."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_zipkin"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            try:
                health_data = json.loads(resp.read().decode())
                status = health_data.get("status", "UP" if healthy else "DOWN")
            except Exception:
                status = "UP" if healthy else "DOWN"
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}", "tool": "check_zipkin", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "check_zipkin", "host": host}
    result: dict = {"host": host, "port": port, "healthy": healthy, "status": status}
    try:
        req2 = urllib.request.Request(f"{scheme}://{host}:{port}/api/v2/services", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req2, timeout=timeout, context=ctx) as resp2:
            services = json.loads(resp2.read().decode())
            result["services"] = services
            result["service_count"] = len(services)
    except Exception:
        pass
    return {"result": result}


@mcp.tool()
def check_komga(host: str, port: int = 25600, timeout: int = 5, https: bool = False) -> dict:
    """Check Komga comics/manga server health via GET /actuator/health. Returns healthy status, server version if available, and library count. Default port 25600."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_komga"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/actuator/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "note": "Auth required"}}
        return {"error": f"HTTP {e.code}: {e.reason}", "tool": "check_komga", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "check_komga", "host": host}
    status = data.get("status", "UNKNOWN")
    result: dict = {"host": host, "port": port, "healthy": healthy and status == "UP", "reachable": healthy, "status": status}
    try:
        req2 = urllib.request.Request(f"{scheme}://{host}:{port}/api/v1/libraries", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req2, timeout=timeout, context=ctx) as resp2:
            libs = json.loads(resp2.read().decode())
            result["library_count"] = len(libs) if isinstance(libs, list) else libs.get("numberOfElements")
    except Exception:
        pass
    return {"result": result}


@mcp.tool()
def check_tubearchivist(host: str, port: int = 8000, timeout: int = 5, https: bool = False) -> dict:
    """Check TubeArchivist (YouTube archiver) health via GET /api/ping/. Returns healthy status and version info. Default port 8000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_tubearchivist"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/ping/", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            try:
                data = json.loads(resp.read().decode())
            except Exception:
                data = {}
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "note": "Auth required"}}
        return {"error": f"HTTP {e.code}: {e.reason}", "tool": "check_tubearchivist", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "check_tubearchivist", "host": host}
    return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": healthy, "version": data.get("version"), "ta_version": data.get("ta_version")}}


@mcp.tool()
def check_mylar3(host: str, port: int = 8090, timeout: int = 5, https: bool = False) -> dict:
    """Check Mylar3 comics manager health via GET /api?apikey=nokey&cmd=getVersion (returns 401/403 if auth required, but proves service is up). Default port 8090."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_mylar3"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    reachable = False
    version: str | None = None
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 302, 303)
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 301, 302, 303, 401, 403)
    except Exception as e:
        return {"error": str(e), "tool": "check_mylar3", "host": host}
    return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "version": version}}


@mcp.tool()
def check_karakeep(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Karakeep (formerly Hoarder) AI bookmark manager health via GET /api/v1/health. Returns healthy/reachable status. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_karakeep"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v1/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": healthy}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_karakeep", "host": host}


@mcp.tool()
def check_maybe(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Maybe personal finance manager reachability via GET /. Returns 200 or 302 when service is up. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_maybe"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 302)
            return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 301, 302)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_maybe", "host": host}


@mcp.tool()
def check_headscale(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Headscale (self-hosted Tailscale control server) health via GET /health. Returns healthy/reachable status. Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_headscale"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": healthy}}
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}", "tool": "check_headscale", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "check_headscale", "host": host}


@mcp.tool()
def check_gitness(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Gitness (Harness git hosting) health via GET /api/v1/health. Returns 200 when service is up. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_gitness"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v1/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": healthy}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_gitness", "host": host}


@mcp.tool()
def check_netbird(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check NetBird VPN management server health via GET /api/v1/self-hosted/setup-keys (returns 200 or 401 when service is up). Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_netbird"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v1/self-hosted/setup-keys", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 401)
            return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401, 403)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_netbird", "host": host}


@mcp.tool()
def check_linkding(host: str, port: int = 9090, timeout: int = 5, https: bool = False) -> dict:
    """Check Linkding bookmark manager health via GET /health. Returns healthy/reachable status. Default port 9090."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_linkding"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": healthy}}
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}", "tool": "check_linkding", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "check_linkding", "host": host}


@mcp.tool()
def check_docmost(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Docmost collaborative wiki/documentation health via GET /api/health. Returns healthy/reachable status. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_docmost"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": healthy}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401, 302)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_docmost", "host": host}


@mcp.tool()
def check_docuseal(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check DocuSeal document signing service reachability via GET /. Returns 200 or 302 when service is up. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_docuseal"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 302)
            return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 301, 302)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_docuseal", "host": host}


@mcp.tool()
def check_grist(host: str, port: int = 8484, timeout: int = 5, https: bool = False) -> dict:
    """Check Grist spreadsheet/database service health via GET /api/docs. Returns 200 or 401 when service is up. Default port 8484."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_grist"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/docs", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status in (200, 401)
            return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": healthy}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401, 403)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_grist", "host": host}


@mcp.tool()
def check_baikal(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Baïkal CalDAV/CardDAV server reachability via GET /. Returns 200 or 302 when service is up. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_baikal"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 302)
            return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 301, 302)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_baikal", "host": host}


@mcp.tool()
def check_firefly_iii(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Firefly III personal finance manager health via GET /api/v1/about (returns 200 with version or 401 if unauthenticated — both confirm service is up). Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_firefly_iii"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v1/about", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "version": data.get("data", {}).get("version")}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401, 403)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_firefly_iii", "host": host}


@mcp.tool()
def check_listmonk(host: str, port: int = 9000, timeout: int = 5, https: bool = False) -> dict:
    """Check listmonk newsletter/mailing list manager health via GET /api/health. Returns healthy/reachable status and version. Default port 9000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_listmonk"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            healthy = resp.status == 200
            return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": healthy, "version": data.get("data", {}).get("version")}}
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}", "tool": "check_listmonk", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "check_listmonk", "host": host}


@mcp.tool()
def check_healthchecks(host: str, port: int = 8000, timeout: int = 5, https: bool = False) -> dict:
    """Check Healthchecks.io (self-hosted) cron job monitoring reachability via GET /. Returns 200 when service is up. Default port 8000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_healthchecks"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 302)
            return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 301, 302)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_healthchecks", "host": host}


@mcp.tool()
def check_shiori(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Shiori bookmark manager reachability via GET /. Returns 200 or 302 (redirect to login) when service is up. Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_shiori"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 302)
            return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 301, 302)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_shiori", "host": host}


@mcp.tool()
def check_openproject(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check OpenProject project management reachability via GET /api/v3/configuration. Returns 200 or 401 when service is up. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_openproject"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v3/configuration", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "edition": data.get("edition")}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401, 403)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_openproject", "host": host}


@mcp.tool()
def check_dozzle(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Dozzle Docker log viewer health via GET /healthcheck. Returns healthy/reachable status. Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_dozzle"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/healthcheck", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            healthy = resp.status == 200
            return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": healthy}}
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}", "tool": "check_dozzle", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "check_dozzle", "host": host}


@mcp.tool()
def check_scrutiny(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Scrutiny disk health monitoring health via GET /api/health. Returns healthy/reachable status. Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_scrutiny"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            healthy = resp.status == 200 and data.get("success", False)
            return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": resp.status == 200}}
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}", "tool": "check_scrutiny", "host": host}
    except Exception as e:
        return {"error": str(e), "tool": "check_scrutiny", "host": host}


@mcp.tool()
def check_radicale(host: str, port: int = 5232, timeout: int = 5, https: bool = False) -> dict:
    """Check Radicale CalDAV/CardDAV server reachability via GET /. Returns 200 or 401 when service is up. Default port 5232."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_radicale"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 401)
            return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_radicale", "host": host}


@mcp.tool()
def check_archivebox(host: str, port: int = 8000, timeout: int = 5, https: bool = False) -> dict:
    """Check ArchiveBox web archiving service reachability via GET /. Returns 200 or 302 when service is up. Default port 8000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_archivebox"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 302)
            return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 301, 302)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_archivebox", "host": host}


@mcp.tool()
def check_leantime(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Leantime project management service reachability via GET /. Returns 200 or 302 when service is up. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_leantime"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 302)
            return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 301, 302)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_leantime", "host": host}


@mcp.tool()
def check_authelia(host: str, port: int = 9091, timeout: int = 5, https: bool = False) -> dict:
    """Check Authelia authentication server health via GET /api/health. Returns healthy when service is up. Default port 9091."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_authelia"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            return {"result": {"host": host, "port": port, "healthy": data.get("status") == "OK", "reachable": True, "status": data.get("status")}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 204)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_authelia", "host": host}


@mcp.tool()
def check_whoogle(host: str, port: int = 5000, timeout: int = 5, https: bool = False) -> dict:
    """Check Whoogle search engine reachability via GET /. Returns healthy when main page loads. Default port 5000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_whoogle"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 302)
            return {"result": {"host": host, "port": port, "healthy": reachable, "reachable": reachable}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 302)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_whoogle", "host": host}


@mcp.tool()
def check_emby(host: str, port: int = 8096, timeout: int = 5, https: bool = False) -> dict:
    """Check Emby Media Server reachability via GET /System/Info/Public. Returns server name and version when healthy. Default port 8096."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_emby"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/System/Info/Public", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "server_name": data.get("ServerName"), "version": data.get("Version")}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_emby", "host": host}


@mcp.tool()
def check_jackett(host: str, port: int = 9117, timeout: int = 5, https: bool = False) -> dict:
    """Check Jackett indexer proxy reachability via GET /health. Returns healthy when service responds. Default port 9117."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_jackett"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_jackett", "host": host}


@mcp.tool()
def check_plex(host: str, port: int = 32400, timeout: int = 5, https: bool = False) -> dict:
    """Check Plex Media Server reachability via GET /identity. Returns server version and machine identifier when healthy. Default port 32400."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_plex"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/identity", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            media_container = data.get("MediaContainer", {})
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "version": media_container.get("version"), "machine_identifier": media_container.get("machineIdentifier")}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_plex", "host": host}


@mcp.tool()
def check_sonarr(host: str, port: int = 8989, timeout: int = 5, https: bool = False) -> dict:
    """Check Sonarr TV series manager reachability via GET /api/v3/health. Returns healthy when service responds. Default port 8989."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_sonarr"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v3/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_sonarr", "host": host}


@mcp.tool()
def check_radarr(host: str, port: int = 7878, timeout: int = 5, https: bool = False) -> dict:
    """Check Radarr movie manager reachability via GET /api/v3/health. Returns healthy when service responds. Default port 7878."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_radarr"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v3/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_radarr", "host": host}


@mcp.tool()
def check_tautulli(host: str, port: int = 8181, timeout: int = 5, https: bool = False) -> dict:
    """Check Tautulli Plex statistics reachability via GET /status. Returns healthy when service responds. Default port 8181."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_tautulli"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/status", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            reachable = resp.status in (200, 302)
            return {"result": {"host": host, "port": port, "healthy": reachable, "reachable": reachable}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 302, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_tautulli", "host": host}


@mcp.tool()
def check_overseerr(host: str, port: int = 5055, timeout: int = 5, https: bool = False) -> dict:
    """Check Overseerr media request manager reachability via GET /api/v1/status. Returns version when healthy. Default port 5055."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_overseerr"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v1/status", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "version": data.get("version"), "commit": data.get("commitTag")}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_overseerr", "host": host}


@mcp.tool()
def check_beszel(host: str, port: int = 8090, timeout: int = 5, https: bool = False) -> dict:
    """Check Beszel server monitoring hub reachability via GET /api/health. Default port 8090."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_beszel"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_beszel", "host": host}


@mcp.tool()
def check_gatus(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Gatus health monitoring dashboard reachability via GET /health. Returns healthy=true when all configured endpoints are up. Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_gatus"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            return {"result": {"host": host, "port": port, "healthy": data.get("healthy", True), "reachable": True}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 503)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": e.code == 200, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_gatus", "host": host}


@mcp.tool()
def check_technitium(host: str, port: int = 5380, timeout: int = 5, https: bool = False) -> dict:
    """Check Technitium DNS Server reachability via GET /api/user/login (returns an API error indicating the server is up). Default port 5380."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_technitium"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/user/login", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            reachable = data.get("status") in ("ok", "error")
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "status": data.get("status")}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_technitium", "host": host}


@mcp.tool()
def check_crowdsec(host: str, port: int = 6060, timeout: int = 5, https: bool = False) -> dict:
    """Check CrowdSec security agent local API reachability via GET /metrics. Default port 6060 (Prometheus metrics endpoint — no auth required)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_crowdsec"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/metrics", headers={"Accept": "text/plain"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_crowdsec", "host": host}


@mcp.tool()
def check_wazuh(host: str, port: int = 55000, timeout: int = 5, https: bool = True) -> dict:
    """Check Wazuh security platform API reachability via GET /. Default port 55000 with HTTPS. Returns 401 when up (auth required but server is responding)."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_wazuh"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_wazuh", "host": host}


@mcp.tool()
def check_nitter(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Nitter Twitter/X frontend reachability via GET /. Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_nitter"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_nitter", "host": host}


@mcp.tool()
def check_redlib(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Redlib (private Reddit frontend) reachability via GET /. Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_redlib"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_redlib", "host": host}


@mcp.tool()
def check_speedtest_tracker(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Speedtest Tracker reachability via GET /api/healthcheck. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_speedtest_tracker"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/healthcheck", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_speedtest_tracker", "host": host}


@mcp.tool()
def check_strapi(host: str, port: int = 1337, timeout: int = 5, https: bool = False) -> dict:
    """Check Strapi headless CMS reachability via GET /api/health-check. Returns status when healthy. Default port 1337."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_strapi"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/health-check", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "status": data.get("data", {}).get("attributes", {}).get("status")}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_strapi", "host": host}


@mcp.tool()
def check_organizr(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Organizr v2 dashboard reachability via GET /api/v2/apps. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_organizr"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v2/apps", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_organizr", "host": host}


@mcp.tool()
def check_heimdall(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Heimdall application dashboard reachability via GET /. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_heimdall"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_heimdall", "host": host}


@mcp.tool()
def check_invidious(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Invidious YouTube frontend reachability via GET /api/v1/stats. Returns software version when healthy. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_invidious"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v1/stats", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            sw = data.get("software", {})
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "version": sw.get("version"), "branch": sw.get("branch")}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_invidious", "host": host}


@mcp.tool()
def check_hoarder(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check Hoarder bookmarks manager reachability via GET /api/v1/health. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_hoarder"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v1/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_hoarder", "host": host}


@mcp.tool()
def check_trilium(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Trilium Notes hierarchical note-taking app reachability via GET /. Default port 8080."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_trilium"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_trilium", "host": host}


@mcp.tool()
def check_kasm(host: str, port: int = 443, timeout: int = 5, https: bool = True) -> dict:
    """Check Kasm Workspaces containerized desktop reachability via GET /. Default port 443 with HTTPS."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_kasm"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_kasm", "host": host}


@mcp.tool()
def check_homarr(host: str, port: int = 7575, timeout: int = 5, https: bool = False) -> dict:
    """Check Homarr dashboard reachability via GET /api/health. Default port 7575."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_homarr"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "status": data.get("status")}}
    except urllib.error.HTTPError as e:
        reachable = e.code in (200, 401)
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_homarr", "host": host}


@mcp.tool()
def check_flame(host: str, port: int = 5005, timeout: int = 5, https: bool = False) -> dict:
    """Check Flame startpage/dashboard reachability via GET /. Default port 5005."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_flame"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_flame", "host": host}


@mcp.tool()
def check_wallos(host: str, port: int = 8282, timeout: int = 5, https: bool = False) -> dict:
    """Check Wallos subscription tracker reachability via GET /. Default port 8282."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_wallos"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_wallos", "host": host}


@mcp.tool()
def check_it_tools(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check IT Tools developer utility hub reachability via GET /. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_it_tools"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_it_tools", "host": host}


@mcp.tool()
def check_kibana(host: str, port: int = 5601, timeout: int = 5, https: bool = False) -> dict:
    """Check Kibana (Elastic Stack UI) reachability via GET /api/status. Default port 5601. Returns overall status color (green/yellow/red) from the health response."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_kibana"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/status", headers={"Accept": "application/json", "kbn-xsrf": "true"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read()
            data = json.loads(body) if body else {}
            status_color = data.get("status", {}).get("overall", {}).get("state", "unknown")
            healthy = status_color == "green"
            return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": True, "http_code": resp.status, "status": status_color}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_kibana", "host": host}


@mcp.tool()
def check_signoz(host: str, port: int = 3301, timeout: int = 5, https: bool = False) -> dict:
    """Check SigNoz (OpenTelemetry observability) reachability via GET /api/v1/health. Default port 3301. Returns status from health response."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_signoz"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/api/v1/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read()
            data = json.loads(body) if body else {}
            status = data.get("status", "unknown")
            healthy = status == "ok"
            return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": True, "http_code": resp.status, "status": status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_signoz", "host": host}


@mcp.tool()
def check_librenms(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check LibreNMS (network monitoring) reachability via GET /. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_librenms"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_librenms", "host": host}


@mcp.tool()
def check_ntopng(host: str, port: int = 3000, timeout: int = 5, https: bool = False) -> dict:
    """Check ntopng (network traffic monitoring) reachability via GET /. Default port 3000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_ntopng"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_ntopng", "host": host}


@mcp.tool()
def check_checkmk(host: str, port: int = 5000, timeout: int = 5, https: bool = False) -> dict:
    """Check Checkmk (IT monitoring) reachability via GET /. Default port 5000."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_checkmk"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_checkmk", "host": host}


@mcp.tool()
def check_icinga(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Icinga (monitoring) reachability via GET /icingaweb2/. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_icinga"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/icingaweb2/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_icinga", "host": host}


@mcp.tool()
def check_zabbix(host: str, port: int = 80, timeout: int = 5, https: bool = False) -> dict:
    """Check Zabbix (enterprise monitoring) reachability via GET /zabbix/. Default port 80."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_zabbix"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/zabbix/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"result": {"host": host, "port": port, "healthy": True, "reachable": True, "http_code": resp.status}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": reachable, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_zabbix", "host": host}


@mcp.tool()
def check_mimir(host: str, port: int = 8080, timeout: int = 5, https: bool = False) -> dict:
    """Check Grafana Mimir (scalable Prometheus) reachability via GET /ready. Default port 8080. Returns ready status from response body."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_mimir"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/ready", headers={"Accept": "text/plain"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace").strip()
            healthy = "ready" in body.lower()
            return {"result": {"host": host, "port": port, "healthy": healthy, "reachable": True, "http_code": resp.status, "status": body}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": False, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_mimir", "host": host}


@mcp.tool()
def check_vector(host: str, port: int = 8686, timeout: int = 5, https: bool = False) -> dict:
    """Check Vector (log pipeline) reachability via GET /health. Default port 8686. Returns healthy status and component details from health response."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "check_vector"}
    host = host.strip()
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read()
            data = json.loads(body) if body else {}
            healthy = data.get("ok", resp.status == 200)
            return {"result": {"host": host, "port": port, "healthy": bool(healthy), "reachable": True, "http_code": resp.status, "response": data}}
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
        return {"result": {"host": host, "port": port, "reachable": reachable, "healthy": False, "http_code": e.code}}
    except Exception as e:
        return {"error": str(e), "tool": "check_vector", "host": host}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
