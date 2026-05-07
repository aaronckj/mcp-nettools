"""Tests for mcp-nettools tools. All network calls are mocked."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest
from mcp_nettools.server import ping


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
