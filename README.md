# mcp-nettools

MCP server for network diagnostics and service health checks. Exposes **235 tools** — from low-level network probes (`ping`, `traceroute`, `port_check`, `cert_check`) to one-shot reachability/health checks for ~180 popular self-hosted services and infrastructure components (databases, message queues, observability stacks, the *arr media stack, and more).

Works with Claude Code, Claude Desktop, or any MCP client. Communicates over stdio.

> Every tool is a hand-written probe that speaks the real protocol or hits the real health endpoint — there are no auto-generated or duplicate tools. The breadth is the point: ask Claude "is my Postgres up?", "what TLS versions does example.com accept?", or "scan the common ports on 192.0.2.10" and it just works.

## Quick Start

### uvx (no install required)

```bash
uvx mcp-nettools
```

### Claude Code

```bash
claude mcp add nettools -- uvx mcp-nettools
```

### Claude Desktop / MCP clients

Add to your MCP config (`~/.config/claude/claude_desktop_config.json` for Claude Desktop, or any client's `mcp.json`):

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

### Docker

```bash
docker run -i --rm ghcr.io/aaronckj/mcp-nettools:latest
```

Or in your MCP config:

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

For the `ping` and `traceroute` tools, the server needs system binaries:
- **Linux:** `apt install iputils-ping traceroute`
- **macOS:** both are pre-installed
- **Docker:** included in the image

All other tools are pure-Python and need no extra binaries.

## Tools

235 tools, grouped by category below.

### Core network diagnostics (13)

| Tool | Description |
|------|-------------|
| `ping` | Ping a host and return reachability, packet loss %, and RTT stats |
| `port_check` | Check if a TCP port is open on a host |
| `port_scan` | Check multiple TCP ports on a host |
| `traceroute` | Trace the network path to a host |
| `get_public_ip` | Return the public IP of the machine running this server, plus basic geolocation |
| `arp_table` | Show ARP/neighbor table entries (IP-to-MAC mappings) as structured records |
| `wake_on_lan` | Send a Wake-on-LAN magic packet to a MAC address |
| `speedtest` | Run a network speed test using the nearest server |
| `tcp_banner` | Connect to any TCP port and read the initial server banner |
| `scan_common_ports` | Scan 17 commonly used ports and report which are open |
| `ping_sweep` | Ping all hosts in an IPv4 CIDR range and report which respond |
| `local_ports` | List listening TCP and UDP ports on the local machine |
| `network_interfaces` | List local network interfaces with IPs, prefix length, and link status |

### DNS, IP & address intelligence (14)

| Tool | Description |
|------|-------------|
| `dns_lookup` | Look up DNS records for a hostname |
| `reverse_dns` | Reverse DNS lookup for an IP address |
| `reverse_dns_bulk` | Reverse DNS lookup for multiple IP addresses at once |
| `subnet_info` | Parse an IPv4/IPv6 CIDR: network address, host range, host count |
| `geolocation` | Geolocation for a public IP: country, region, city, ISP, coordinates |
| `whois` | Look up WHOIS registration data for a domain or IP address |
| `mac_lookup` | Look up the vendor/manufacturer for a MAC address (OUI database) |
| `dns_bulk_lookup` | Look up DNS records for multiple hostnames in one call |
| `dns_propagation` | Check DNS propagation across 4 major public resolvers |
| `bgp_lookup` | Look up BGP/ASN information for a public IP via Team Cymru |
| `dnssec_check` | Check DNSSEC status: DNSKEY records, RRSIG signatures |
| `check_spf` | Check the SPF record for a domain |
| `check_dkim` | Check whether a DKIM public key is published for a domain and selector |
| `check_dmarc` | Check the DMARC policy for a domain |

### TLS & certificates (3)

| Tool | Description |
|------|-------------|
| `cert_check` | SSL certificate expiry, issued date, issuer, SANs, days remaining |
| `tls_version_check` | Test which TLS protocol versions a server accepts (TLS 1.2, TLS 1.3) |
| `cert_check_bulk` | Check TLS certificates for multiple hosts in one call |

### HTTP & web (10)

| Tool | Description |
|------|-------------|
| `http_check` | Check an HTTP/HTTPS URL: status, response time, content type, server header |
| `http_redirect_chain` | Follow an HTTP/HTTPS URL through all redirects and return every hop |
| `check_security_headers` | Report which HTTP security headers are present or missing |
| `http_security_headers` | Audit HTTP security headers on a web server |
| `http_post` | Send an HTTP POST request with a body |
| `http_put` | Send an HTTP PUT request with a body |
| `http_delete` | Send an HTTP DELETE request |
| `http_patch` | Send an HTTP PATCH request with a body |
| `check_wordpress` | Check WordPress site health via GET /wp-json/ |
| `check_ghost` | Check Ghost blog platform health |

### Mail, remote-access & network protocols (14)

| Tool | Description |
|------|-------------|
| `smtp_check` | SMTP connectivity, banner, capabilities, STARTTLS support |
| `imap_check` | Check IMAP server connectivity |
| `pop3_check` | Check POP3 server connectivity |
| `ssh_check` | SSH connectivity and server banner (version string) |
| `check_rdp` | Check whether a Remote Desktop Protocol server is reachable |
| `check_vnc` | Connect to a VNC server and read the RFB protocol banner |
| `check_ldap` | Check LDAP server connectivity and protocol |
| `check_smb` | Check SMB/CIFS file-sharing service reachability |
| `check_nfs` | Check NFS file server availability |
| `ftp_check` | Connect to an FTP server and read its banner |
| `ntp_check` | NTP reachability and clock offset relative to local time |
| `snmp_check` | SNMPv2c GetRequest for sysDescr over UDP |
| `check_sip` | Check a SIP server via an OPTIONS probe |
| `check_mqtt` | Connect to an MQTT broker and send a CONNECT packet (v3.1.1) |

### Databases (16)

| Tool | Description |
|------|-------------|
| `mysql_check` | MySQL/MariaDB server greeting and version |
| `check_postgres` | PostgreSQL server version from the startup response |
| `check_mongodb` | MongoDB hello command via the wire protocol |
| `check_redis` | Redis PING/PONG check |
| `check_memcached` | Memcached version check |
| `check_cassandra` | Apache Cassandra via the CQL binary protocol |
| `check_clickhouse` | ClickHouse OLAP database via HTTP /ping |
| `check_neo4j` | Neo4j graph database via the HTTP API |
| `check_couchdb` | Apache CouchDB version and node name |
| `check_influxdb` | InfluxDB server health |
| `check_elasticsearch` | Elasticsearch/OpenSearch cluster health |
| `check_opensearch` | OpenSearch cluster health via /_cluster/health |
| `check_etcd` | etcd v3 cluster health |
| `check_victoriametrics` | VictoriaMetrics time-series DB health |
| `check_nocodb` | NocoDB no-code database platform health |
| `check_pocketbase` | PocketBase backend health |

### Message queues & streaming (3)

| Tool | Description |
|------|-------------|
| `check_kafka` | Apache Kafka broker availability |
| `check_rabbitmq` | RabbitMQ health via the management plugin API |
| `check_zookeeper` | ZooKeeper health via the `ruok` command |

### Containers, orchestration & identity (15)

| Tool | Description |
|------|-------------|
| `check_docker_api` | Docker daemon REST API via GET /_ping |
| `check_kubernetes_api` | Kubernetes API server health via /healthz and /version |
| `check_consul` | Consul agent health and cluster leader |
| `check_vault` | HashiCorp Vault server health |
| `check_traefik` | Traefik reverse proxy health |
| `check_minio` | MinIO object storage liveness/readiness |
| `check_portainer` | Portainer container management UI health |
| `check_cockpit` | Cockpit Linux server management web UI health |
| `check_headscale` | Headscale (self-hosted Tailscale control server) health |
| `check_netbird` | NetBird VPN management server health |
| `check_authentik` | Authentik identity provider health |
| `check_authelia` | Authelia authentication server health |
| `check_keycloak` | Keycloak identity server health |
| `check_vaultwarden` | Vaultwarden (Bitwarden-compatible) password manager health |
| `check_bitwarden` | Bitwarden (Unified) server health |

### Observability, monitoring & network security (33)

| Tool | Description |
|------|-------------|
| `check_prometheus` | Prometheus monitoring service health |
| `check_grafana` | Grafana observability platform health |
| `check_loki` | Grafana Loki log aggregation health |
| `check_alertmanager` | Prometheus Alertmanager health |
| `check_tempo` | Grafana Tempo distributed tracing health |
| `check_jaeger` | Jaeger distributed tracing UI and query API |
| `check_zipkin` | Zipkin distributed tracing health and service count |
| `check_mimir` | Grafana Mimir (scalable Prometheus) readiness |
| `check_vector` | Vector log pipeline health |
| `check_signoz` | SigNoz (OpenTelemetry observability) health |
| `check_kibana` | Kibana (Elastic Stack UI) status |
| `check_uptime_kuma` | Uptime Kuma monitoring health |
| `check_gatus` | Gatus health monitoring dashboard |
| `check_healthchecks` | Healthchecks.io (self-hosted) cron monitoring |
| `check_netdata` | Netdata real-time performance monitoring |
| `check_glances` | Glances system monitoring server health |
| `check_beszel` | Beszel server monitoring hub |
| `check_dashdot` | Dashdot server stats dashboard |
| `check_dozzle` | Dozzle Docker log viewer health |
| `check_scrutiny` | Scrutiny disk health monitoring |
| `check_changedetection` | changedetection.io web change monitoring |
| `check_speedtest_tracker` | Speedtest Tracker health |
| `check_librenms` | LibreNMS network monitoring |
| `check_ntopng` | ntopng network traffic monitoring |
| `check_checkmk` | Checkmk IT monitoring |
| `check_icinga` | Icinga monitoring |
| `check_zabbix` | Zabbix enterprise monitoring |
| `check_pihole` | Pi-hole DNS ad blocker status |
| `check_adguard` | AdGuard Home DNS filter health |
| `check_technitium` | Technitium DNS Server reachability |
| `check_crowdsec` | CrowdSec security agent local API |
| `check_wazuh` | Wazuh security platform API |
| `check_frigate` | Frigate NVR (network video recorder) health |

### Git, CI/CD & developer tools (15)

| Tool | Description |
|------|-------------|
| `check_gitea` | Gitea/Forgejo git server health |
| `check_forgejo` | Forgejo (Gitea fork) git server health |
| `check_gitlab` | GitLab instance health |
| `check_gitness` | Gitness (Harness git hosting) health |
| `check_code_server` | code-server (VSCode in browser) health |
| `check_filebrowser` | File Browser web-based file manager health |
| `check_n8n` | n8n workflow automation platform health |
| `check_windmill` | Windmill workflow automation platform health |
| `check_directus` | Directus headless CMS health |
| `check_strapi` | Strapi headless CMS reachability |
| `check_appwrite` | Appwrite open-source BaaS health |
| `check_hoppscotch` | Hoppscotch self-hosted API testing backend health |
| `check_stirling_pdf` | Stirling-PDF tools server health |
| `check_flaresolverr` | FlareSolverr Cloudflare bypass proxy health |
| `check_it_tools` | IT Tools developer utility hub reachability |

### Media servers & *arr stack (31)

| Tool | Description |
|------|-------------|
| `check_plex` | Plex Media Server reachability |
| `check_jellyfin` | Jellyfin media server health |
| `check_emby` | Emby Media Server reachability |
| `check_navidrome` | Navidrome music streaming server health |
| `check_audiobookshelf` | Audiobookshelf audiobook and podcast server health |
| `check_kavita` | Kavita manga/comic/book reader server health |
| `check_komga` | Komga comics/manga server health |
| `check_calibre_web` | Calibre-Web ebook library server health |
| `check_immich` | Immich photo management server health |
| `check_photoprism` | PhotoPrism photo management server health |
| `check_tubearchivist` | TubeArchivist (YouTube archiver) health |
| `check_sonarr` | Sonarr TV series manager reachability |
| `check_radarr` | Radarr movie manager reachability |
| `check_lidarr` | Lidarr music collection manager health |
| `check_readarr` | Readarr book/eBook collection manager health |
| `check_bazarr` | Bazarr subtitle management server health |
| `check_prowlarr` | Prowlarr indexer manager health |
| `check_jackett` | Jackett indexer proxy reachability |
| `check_overseerr` | Overseerr media request manager reachability |
| `check_jellyseerr` | Jellyseerr media request/discovery manager health |
| `check_tautulli` | Tautulli Plex statistics reachability |
| `check_qbittorrent` | qBittorrent Web UI health |
| `check_transmission` | Transmission BitTorrent client RPC health |
| `check_sabnzbd` | SABnzbd usenet downloader health |
| `check_nzbget` | NZBGet usenet downloader health |
| `check_mylar3` | Mylar3 comics manager health |
| `check_searxng` | SearXNG meta-search engine availability |
| `check_whoogle` | Whoogle search engine reachability |
| `check_invidious` | Invidious YouTube frontend reachability |
| `check_nitter` | Nitter Twitter/X frontend reachability |
| `check_redlib` | Redlib (private Reddit frontend) reachability |

### Self-hosted apps & productivity (67)

| Tool | Description |
|------|-------------|
| `check_nextcloud` | Nextcloud/ownCloud instance health |
| `check_seafile` | Seafile file sync and share server health |
| `check_syncthing` | Syncthing file sync service health |
| `check_homeassistant` | Home Assistant health |
| `check_paperless` | Paperless-NGX document management health |
| `check_outline` | Outline wiki/knowledge base health |
| `check_bookstack` | BookStack wiki platform health |
| `check_wikijs` | Wiki.js health |
| `check_dokuwiki` | DokuWiki health |
| `check_docmost` | Docmost collaborative wiki/documentation health |
| `check_hedgedoc` | HedgeDoc collaborative markdown notes health |
| `check_trilium` | Trilium Notes hierarchical note-taking reachability |
| `check_memos` | Memos lightweight notes server health |
| `check_joplin_server` | Joplin Server note-syncing backend health |
| `check_onlyoffice` | OnlyOffice Document Server health |
| `check_collabora` | Collabora Online Office server health |
| `check_grist` | Grist spreadsheet/database service health |
| `check_miniflux` | Miniflux RSS reader health |
| `check_freshrss` | FreshRSS feed aggregator availability |
| `check_mealie` | Mealie recipe manager health |
| `check_tandoor` | Tandoor recipe manager health |
| `check_grocy` | Grocy grocery and household management health |
| `check_monica` | Monica personal CRM availability |
| `check_vikunja` | Vikunja task manager health |
| `check_planka` | Planka kanban board health |
| `check_kimai` | Kimai time-tracking application health |
| `check_snipe_it` | Snipe-IT IT asset management health |
| `check_openproject` | OpenProject project management reachability |
| `check_leantime` | Leantime project management reachability |
| `check_organizr` | Organizr v2 dashboard reachability |
| `check_heimdall` | Heimdall application dashboard reachability |
| `check_homarr` | Homarr dashboard health |
| `check_homepage` | Homepage dashboard (gethomepage.dev) health |
| `check_flame` | Flame startpage/dashboard reachability |
| `check_kasm` | Kasm Workspaces containerized desktop reachability |
| `check_guacamole` | Apache Guacamole remote desktop gateway |
| `check_actual_budget` | Actual Budget personal finance health |
| `check_firefly_iii` | Firefly III personal finance manager health |
| `check_maybe` | Maybe personal finance manager reachability |
| `check_invoiceninja` | Invoice Ninja health |
| `check_wallos` | Wallos subscription tracker reachability |
| `check_linkwarden` | Linkwarden bookmark manager availability |
| `check_linkding` | Linkding bookmark manager health |
| `check_shiori` | Shiori bookmark manager reachability |
| `check_hoarder` | Hoarder bookmarks manager reachability |
| `check_karakeep` | Karakeep (formerly Hoarder) AI bookmark manager health |
| `check_wallabag` | Wallabag read-it-later service availability |
| `check_archivebox` | ArchiveBox web archiving service reachability |
| `check_baikal` | Baïkal CalDAV/CardDAV server reachability |
| `check_radicale` | Radicale CalDAV/CardDAV server reachability |
| `check_mattermost` | Mattermost team messaging server health |
| `check_matrix_synapse` | Matrix Synapse homeserver health |
| `check_discourse` | Discourse forum health |
| `check_ntfy` | ntfy push notification server health |
| `check_gotify` | Gotify push notification server health |
| `check_listmonk` | listmonk newsletter/mailing list manager health |
| `check_plausible` | Plausible Analytics health |
| `check_umami` | Umami privacy-focused analytics health |
| `check_matomo` | Matomo web analytics health |
| `check_limesurvey` | LimeSurvey survey platform health |
| `check_rallly` | Rallly scheduling/polls application health |
| `check_penpot` | Penpot open-source design tool health |
| `check_zipline` | Zipline file sharing server health |
| `check_docuseal` | DocuSeal document signing service reachability |
| `check_ollama` | Ollama LLM server health |
| `check_open_webui` | Open WebUI (Ollama/LLM frontend) health |
| `check_anythingllm` | AnythingLLM (self-hosted RAG/AI workspace) health |

### Server utilities (1)

| Tool | Description |
|------|-------------|
| `health_check` | Liveness check returning `{"status": "healthy", "service": "nettools"}` |

## License

MIT
