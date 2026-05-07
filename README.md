# mcp-nettools

MCP server for network diagnostics. Exposes 8 tools for use with Claude Code, Claude Desktop, or any MCP client.

## Tools

| Tool | Description |
|------|-------------|
| `ping` | ICMP ping — reachability and round-trip times |
| `dns_lookup` | DNS record lookup (A, AAAA, MX, TXT, NS, CNAME) |
| `port_check` | TCP port open/closed check |
| `traceroute` | Network path tracing |
| `speedtest` | Download/upload speed test via nearest server |
| `wake_on_lan` | Send WoL magic packet to a MAC address |
| `cert_check` | SSL certificate expiry, issuer, days remaining |
| `mac_lookup` | MAC address OUI vendor lookup |

## Quick Start

### uvx (no install required)

```bash
uvx mcp-nettools
```

### Docker

```bash
docker run -i ghcr.io/aaronckj/mcp-nettools:latest
```

### Claude Code

```bash
claude mcp add nettools -- uvx mcp-nettools
```

### Claude Desktop

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "nettools": {
      "command": "uvx",
      "args": ["mcp-nettools"]
    }
  }
}
```

Or with Docker:

```json
{
  "mcpServers": {
    "nettools": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/aaronckj/mcp-nettools:latest"]
    }
  }
}
```

## Requirements

For `ping` and `traceroute` tools, the server needs system binaries:
- **Linux:** `apt install iputils-ping traceroute`
- **macOS:** both are pre-installed
- **Docker:** included in the image

## License

MIT
