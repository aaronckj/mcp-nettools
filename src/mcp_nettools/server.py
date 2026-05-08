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
def dns_lookup(host: str, record_type: str = "A", nameserver: str = "") -> dict:
    """Look up DNS records for a hostname. record_type: A, AAAA, MX, TXT, NS, CNAME, PTR, SOA, SRV. nameserver: optional custom resolver IP (e.g., '8.8.8.8' for Google DNS, '1.1.1.1' for Cloudflare)."""
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
        if nameserver and nameserver.strip():
            try:
                ipaddress.ip_address(nameserver.strip())
            except ValueError:
                return {"error": f"Invalid nameserver IP: '{nameserver}'", "tool": "dns_lookup"}
            resolver.nameservers = [nameserver.strip()]
        answers = resolver.resolve(host, record_type)
        return {
            "host": host,
            "record_type": record_type,
            "nameserver": nameserver.strip() if nameserver and nameserver.strip() else None,
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
    workers = min(len(port_list), 50)
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
                cert_der = s.getpeercert(binary_form=True)
        fmt = "%b %d %H:%M:%S %Y %Z"
        not_after = datetime.strptime(cert["notAfter"], fmt).replace(tzinfo=timezone.utc)
        days_remaining = (not_after - datetime.now(timezone.utc)).days
        sans = [v for _type, v in cert.get("subjectAltName", [])]
        fingerprint = hashlib.sha256(cert_der).hexdigest() if cert_der else None
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
            "san": sans,
            "sha256_fingerprint": fingerprint,
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
    """Parse an IPv4 or IPv6 CIDR block: network address, host range, host count, and whether it is a private range. IPv4 also returns broadcast and netmask."""
    if not cidr or not cidr.strip():
        return {"error": "cidr must not be empty", "tool": "subnet_info"}
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return {"error": str(e), "tool": "subnet_info"}

    if isinstance(net, ipaddress.IPv4Network):
        host_list = list(net.hosts())
        return {
            "result": {
                "version": 4,
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
        results = st.results
        return {
            "download_mbps": round(st.download() / 1_000_000, 2),
            "upload_mbps": round(st.upload() / 1_000_000, 2),
            "ping_ms": results.ping,
            "server": (results.server or {}).get("name"),
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
    if not mac or not mac.strip():
        return {"error": "mac must not be empty", "tool": "mac_lookup"}
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
        return {"mac": mac, "vendor": vendor}
    except Exception as e:
        return {"error": str(e), "tool": "mac_lookup", "mac": mac}



@mcp.tool()
def smtp_check(host: str, port: int = 25, timeout: int = 10, check_starttls: bool = True) -> dict:
    """Check an SMTP server: connectivity, banner, advertised capabilities, and STARTTLS support. port: 25 (SMTP), 465 (SMTPS/SSL), 587 (submission). check_starttls: attempt STARTTLS upgrade on port 25/587."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "smtp_check"}
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
    timeout = min(max(1, timeout), 30)
    # NTPv3 client request: LI=0, VN=3, Mode=3
    NTP_PACKET = b"\x1b" + b"\x00" * 47
    NTP_DELTA = 2208988800  # seconds between NTP epoch (1900) and Unix epoch (1970)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            send_time = time.time()
            s.sendto(NTP_PACKET, (host, port))
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
    host_list = [h.strip() for h in hosts.split(",") if h.strip()]
    if not host_list:
        return {"error": "No valid hosts specified", "tool": "dns_bulk_lookup"}
    if len(host_list) > 20:
        return {"error": f"Too many hosts ({len(host_list)}). Maximum 20 per call.", "tool": "dns_bulk_lookup"}
    record_type = record_type.upper()
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

    results: dict = {}
    for host in host_list:
        try:
            answers = resolver.resolve(host, record_type)
            results[host] = {
                "records": [str(r) for r in answers],
                "ttl": answers.rrset.ttl if answers.rrset else None,
            }
        except dns.resolver.NXDOMAIN:
            results[host] = {"error": "NXDOMAIN — domain does not exist"}
        except dns.resolver.NoAnswer:
            results[host] = {"error": f"No {record_type} records found"}
        except Exception as e:
            results[host] = {"error": str(e)}

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
    timeout = min(max(1, timeout), 30)
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout)
        welcome = ftp.getwelcome()
        anon_ok = False
        try:
            ftp.login()
            anon_ok = True
        except ftplib.all_errors:
            pass
        try:
            ftp.quit()
        except Exception:
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
    except Exception as e:
        return {"error": str(e), "tool": "ftp_check", "host": host, "detail": type(e).__name__}


@mcp.tool()
def tcp_banner(host: str, port: int, timeout: int = 5) -> dict:
    """Connect to any TCP port and read the initial server banner. Useful for identifying unknown services or verifying custom TCP servers. Returns raw banner text."""
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "tcp_banner"}
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
    timeout = min(max(1, timeout), 30)
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            raw = sock.recv(256)
            banner = raw.decode("utf-8", errors="replace").strip()
            try:
                sock.sendall(b"SSH-2.0-Claude_1.0
")
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
def imap_check(host: str, port: int = 143, timeout: int = 10) -> dict:
    """Check IMAP server connectivity. Reads server greeting and capabilities. Tests STARTTLS for port 143; uses implicit TLS for port 993. Does not authenticate."""
    import imaplib
    if not host or not host.strip():
        return {"error": "host must not be empty", "tool": "imap_check"}
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
    except Exception as e:
        return {"error": str(e), "tool": "imap_check", "host": host, "detail": type(e).__name__}
    finally:
        socket.setdefaulttimeout(old_timeout)


@mcp.tool()
def http_redirect_chain(url: str, max_redirects: int = 10, timeout: int = 10) -> dict:
    """Follow an HTTP/HTTPS URL through all redirects and return every hop with status code and Location header. Useful for debugging redirect loops or verifying HTTPS redirect configuration."""
    if not url or not url.strip():
        return {"error": "url must not be empty", "tool": "http_redirect_chain"}
    max_redirects = min(max(1, max_redirects), 20)
    timeout = min(max(1, timeout), 30)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(_NoRedirect())
    chain = []
    current = url.strip()

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
                    from urllib.parse import urljoin
                    location = urljoin(current, location)
                current = location
        except Exception as e:
            chain.append({"hop": hop, "url": current, "error": str(e), "final": True})
            break
    else:
        chain.append({"hop": max_redirects + 1, "url": current, "error": "max_redirects exceeded", "final": True})

    return {
        "result": {
            "original_url": url.strip(),
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
    timeout = min(max(1, timeout), 30)
    try:
        req = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                status_code = resp.status
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in e.headers.items()}
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
            null_pos = data.find(b" ", 5)
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
    timeout = min(max(1, timeout), 30)
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"*1
$4
PING
")
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
def ping_sweep(network: str, timeout: int = 1) -> dict:
    """Ping all hosts in an IPv4 CIDR range and report which respond. Max /24 (256 addresses). Runs parallel pings. timeout: per-host wait in seconds. Returns list of alive IPs."""
    if not network or not network.strip():
        return {"error": "network must not be empty", "tool": "ping_sweep"}
    timeout = min(max(1, timeout), 10)
    try:
        net = ipaddress.IPv4Network(network.strip(), strict=False)
    except ValueError as e:
        return {"error": str(e), "tool": "ping_sweep"}
    if net.num_addresses > 256:
        return {"error": f"Network too large ({net.num_addresses} addresses). Maximum /24 (256).", "tool": "ping_sweep"}

    hosts = list(net.hosts()) if net.prefixlen < 32 else [net.network_address]

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
    record_type = record_type.upper()
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
    consistent = len(set(record_sets)) <= 1

    return {
        "result": {
            "domain": domain,
            "record_type": record_type,
            "consistent": consistent,
            "propagated": consistent and bool(record_sets) and len(record_sets) == len(_DNS_RESOLVERS),
            "resolvers": results,
        }
    }

def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
