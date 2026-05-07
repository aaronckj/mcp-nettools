"""Tests for mcp-nettools tools. All network calls are mocked."""

from __future__ import annotations

import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp_nettools.server import cert_check, dns_lookup, mac_lookup, ping, port_check, speedtest, traceroute, wake_on_lan


def test_ping_reachable():
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "4 packets transmitted, 4 received"
    with patch("subprocess.run", return_value=mock_result):
        result = ping("8.8.8.8")
    assert result["reachable"] is True
    assert result["host"] == "8.8.8.8"
    assert "output" in result


def test_ping_unreachable():
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = "4 packets transmitted, 0 received"
    with patch("subprocess.run", return_value=mock_result):
        result = ping("192.0.2.1")
    assert result["reachable"] is False


def test_ping_timeout_error():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ping", 5)):
        result = ping("192.0.2.1")
    assert "error" in result
    assert result["tool"] == "ping"
    assert result["host"] == "192.0.2.1"


def test_dns_lookup_a_record():
    mock_record = MagicMock()
    mock_record.__str__ = lambda self: "8.8.8.8"
    with patch("dns.resolver.resolve", return_value=[mock_record]):
        result = dns_lookup("google.com")
    assert result["host"] == "google.com"
    assert result["record_type"] == "A"
    assert result["records"] == ["8.8.8.8"]


def test_dns_lookup_custom_type():
    mock_record = MagicMock()
    mock_record.__str__ = lambda self: "v=spf1 include:_spf.google.com ~all"
    with patch("dns.resolver.resolve", return_value=[mock_record]):
        result = dns_lookup("google.com", record_type="TXT")
    assert result["record_type"] == "TXT"


def test_dns_lookup_nxdomain():
    with patch("dns.resolver.resolve", side_effect=Exception("NXDOMAIN")):
        result = dns_lookup("nonexistent.invalid")
    assert "error" in result
    assert result["tool"] == "dns_lookup"
    assert result["host"] == "nonexistent.invalid"


def test_port_check_open():
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=None)
    with patch("socket.socket", return_value=mock_sock):
        result = port_check("8.8.8.8", 53)
    assert result["open"] is True
    assert result["host"] == "8.8.8.8"
    assert result["port"] == 53


def test_port_check_closed():
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 111
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=None)
    with patch("socket.socket", return_value=mock_sock):
        result = port_check("8.8.8.8", 9999)
    assert result["open"] is False


def test_port_check_error():
    with patch("socket.socket", side_effect=OSError("Network unreachable")):
        result = port_check("192.0.2.1", 80)
    assert "error" in result
    assert result["tool"] == "port_check"
    assert result["port"] == 80


def test_traceroute_success():
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "traceroute to 8.8.8.8\n 1  10.0.0.1  1ms\n 2  8.8.8.8  5ms"
    with patch("subprocess.run", return_value=mock_result):
        result = traceroute("8.8.8.8")
    assert result["host"] == "8.8.8.8"
    assert "output" in result
    assert result["returncode"] == 0


def test_traceroute_timeout():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("traceroute", 60)):
        result = traceroute("192.0.2.1")
    assert "error" in result
    assert result["tool"] == "traceroute"
    assert result["host"] == "192.0.2.1"


def test_speedtest_success():
    mock_st = MagicMock()
    mock_st.download.return_value = 500_000_000
    mock_st.upload.return_value = 100_000_000
    mock_st.results.ping = 12.5
    mock_st.results.server = {"name": "Test Server"}
    with patch("mcp_nettools.server._speedtest_lib.Speedtest", return_value=mock_st):
        result = speedtest()
    assert result["download_mbps"] == 500.0
    assert result["upload_mbps"] == 100.0
    assert result["ping_ms"] == 12.5
    assert result["server"] == "Test Server"


def test_speedtest_error():
    with patch("mcp_nettools.server._speedtest_lib.Speedtest", side_effect=Exception("No servers")):
        result = speedtest()
    assert "error" in result
    assert result["tool"] == "speedtest"


def test_wake_on_lan_default_broadcast():
    with patch("mcp_nettools.server.send_magic_packet") as mock_wol:
        result = wake_on_lan("aa:bb:cc:dd:ee:ff")
    mock_wol.assert_called_once_with("aa:bb:cc:dd:ee:ff", ip_address="255.255.255.255")
    assert result["sent"] is True
    assert result["mac"] == "aa:bb:cc:dd:ee:ff"
    assert result["broadcast"] == "255.255.255.255"


def test_wake_on_lan_custom_broadcast():
    with patch("mcp_nettools.server.send_magic_packet") as mock_wol:
        result = wake_on_lan("aa:bb:cc:dd:ee:ff", broadcast="10.0.0.255")
    mock_wol.assert_called_once_with("aa:bb:cc:dd:ee:ff", ip_address="10.0.0.255")
    assert result["broadcast"] == "10.0.0.255"


def test_wake_on_lan_invalid_mac():
    with patch("mcp_nettools.server.send_magic_packet", side_effect=ValueError("Invalid MAC")):
        result = wake_on_lan("not-a-mac")
    assert "error" in result
    assert result["tool"] == "wake_on_lan"
    assert result["mac"] == "not-a-mac"


def test_cert_check_valid():
    mock_cert = {
        "notAfter": "Dec 31 23:59:59 2099 GMT",
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Let's Encrypt"),),),
    }
    mock_sock = MagicMock()
    mock_sock.getpeercert.return_value = mock_cert
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_sock
    with patch("ssl.create_default_context", return_value=mock_ctx):
        result = cert_check("example.com")
    assert result["host"] == "example.com"
    assert result["port"] == 443
    assert result["valid"] is True
    assert result["days_remaining"] > 0
    assert result["subject"] == {"commonName": "example.com"}
    assert result["issuer"] == {"organizationName": "Let's Encrypt"}


def test_cert_check_custom_port():
    mock_cert = {
        "notAfter": "Dec 31 23:59:59 2099 GMT",
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Self-Signed"),),),
    }
    mock_sock = MagicMock()
    mock_sock.getpeercert.return_value = mock_cert
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_sock
    with patch("ssl.create_default_context", return_value=mock_ctx):
        result = cert_check("example.com", port=8443)
    assert result["port"] == 8443


def test_cert_check_error():
    with patch("ssl.create_default_context", side_effect=Exception("Connection refused")):
        result = cert_check("nonexistent.invalid")
    assert "error" in result
    assert result["tool"] == "cert_check"
    assert result["host"] == "nonexistent.invalid"


@pytest.mark.asyncio
async def test_mac_lookup_known_vendor():
    mock_lookup = AsyncMock()
    mock_lookup.lookup = AsyncMock(return_value="Apple, Inc.")
    with patch("mcp_nettools.server.AsyncMacLookup", return_value=mock_lookup):
        result = await mac_lookup("d0:11:e5:0f:be:b7")
    assert result["mac"] == "d0:11:e5:0f:be:b7"
    assert result["vendor"] == "Apple, Inc."


@pytest.mark.asyncio
async def test_mac_lookup_unknown():
    mock_lookup = AsyncMock()
    mock_lookup.lookup = AsyncMock(side_effect=Exception("Unknown vendor"))
    with patch("mcp_nettools.server.AsyncMacLookup", return_value=mock_lookup):
        result = await mac_lookup("ff:ff:ff:ff:ff:ff")
    assert "error" in result
    assert result["tool"] == "mac_lookup"
    assert result["mac"] == "ff:ff:ff:ff:ff:ff"
