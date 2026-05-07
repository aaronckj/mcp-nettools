"""Tests for mcp-nettools tools. All network calls are mocked."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest
from mcp_nettools.server import dns_lookup, ping, port_check, traceroute


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
