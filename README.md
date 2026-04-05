# Mailcow Monitoring v1.1 for Zabbix

Complete monitoring solution for Mailcow-Dockerized with Zabbix Agent 2. 307 metrics, 71 triggers, 19 dashboards — secure by design, installed in 5 minutes.

[Detailed Documentation](MAILCOW-MONITORING-DOKU.md)

## Architecture

```
systemd timer (60s) → mailcow-collector.py (root)
  → /var/tmp/mailcow-monitor.json          (main cache, 60s)
  → /var/tmp/mailcow-monitor-slow.json     (slow cache, 1h)
  → /var/tmp/mailcow-monitor-mailflow.json (mailflow cache, 5m)
  → /var/tmp/mailcow-monitor-version.json  (version cache, 1h)
    → Zabbix Agent 2 (zabbix user) → mailcow-reader.sh → reads JSON
```

The collector runs as root (needs Docker/MySQL access) and writes metrics to world-readable JSON files. The Zabbix Agent only reads those files — no Docker access, no sudo, no UnsafeUserParameters required.

## What's Monitored

| Module | Metrics | Description |
|--------|---------|-------------|
| Postfix | 16 | Queue, connections, deferred/bounced, SASL failures |
| Postfix Logs | 11 | Relay denied, RBL rejects, TLS errors, quota warnings |
| Postscreen | 9 | Pass/reject/DNSBL/pregreet (auto-detected) |
| Dovecot | 10 | Connections, login failures, IMAP disconnects |
| Rspamd | 14 | Spam/ham ratio, reject rate, greylist, actions |
| Rspamd Bayes | 5 | Training status: untrained → low → good → excellent |
| Security | 13 | Fail2ban, RBL blacklist, DNS records, open relay |
| Security Audit | 6 | DANE/TLSA, MTA-STS, TLS-RPT, BIMI — score 0-7 |
| Disk & Inodes | 28 | Root, Docker, vmail, log partitions + inode usage + swap |
| Mailboxes & Domains | 10 | Quota usage, top 5 mailboxes |
| Mailflow | 28 | Received/delivered/bounced + anomaly detection |
| ClamAV | 8 | Signature age, DB version, scan status |
| Watchdog | 18 | Health status for all 15 Mailcow services |
| Docker | 7+LLD | CPU, RAM, restarts per container |
| TLS/Certificates | 12 | HTTPS, IMAPS, Submission, SMTP banner — days until expiry |
| MySQL Health | 11 | Connections, threads, InnoDB hit rate, DB size |
| Redis | 10 | Memory, keyspace hits, clients, uptime |
| Nginx | 8 | Active connections, requests, 4xx/5xx errors (5-min window) |
| Unbound DNS | 8 | Queries, cache hit rate, NXDOMAIN, memory |
| Backup | 9 | Age, size, count, missing backups |
| + 8 more | ... | SOGo, Quarantine, Queue Age, Sync Jobs, Updates, Aliases, NTP, Ratelimit |

**Total: 307 UserParameters · 29 collector modules · 71 triggers · 19 dashboards**

## Key Features

### Anomaly Detection
Instead of fixed thresholds, 5 baseline triggers use `trendavg()` to learn what's normal over a week and alert on deviations:

| Metric | Spike | Drop |
|--------|-------|------|
| Received | >5× weekly avg | <20% weekly avg |
| Rejected | >10× weekly avg | — |
| Bounced | >5× weekly avg | — |
| Deferred | >5× weekly avg | — |

### Security Audit Score (0-7)
Checks SPF, DKIM, DMARC plus DANE/TLSA, MTA-STS, TLS-RPT and BIMI. Trigger alerts when score drops below 3.

### Low-Level Discovery
4 LLD rules automatically discover and monitor all domains, mailboxes, sync jobs and Docker containers individually.

### Performance (v1.1)
- **Single `docker ps`** — all 12 containers discovered in one call instead of 12 individual calls
- **Single `awk` pass** — `postfix_log_analysis.sh` replaced 20 `grep` calls with one `awk` script
- **Parallel RBL queries** — `check_rbl.sh` runs all 10 DNS lookups concurrently (1–2s vs 5–10s)
- **Time-bounded Nginx errors** — 4xx/5xx counted over a fixed 5-minute window (`docker logs --since 5m`)
- **SIGTERM handler** — collector cleans up `.tmp` files on shutdown

## Requirements

- Mailcow-Dockerized (running)
- Zabbix Server + Zabbix Agent 2
- Zabbix 7.0
- **Required:** `python3`, `docker`
- **Optional:** `dig` (dnsutils), `openssl`, `nc` (netcat), `pflogsumm`, `jq`

```bash
apt install pflogsumm dnsutils openssl netcat-openbsd jq
```

## Installation

```bash
git clone https://github.com/linuser/Mailcow-Zabbix-Monitoring.git
cd Mailcow-Zabbix-Monitoring
sudo ./install.sh
```

The installer checks for required dependencies (`python3`, `docker`) and warns about optional ones (`dig`, `openssl`, `nc`, `pflogsumm`, `jq`).

Then in Zabbix:
1. **Data collection → Templates → Import** → select `templates/mailcow-complete-monitoring.yaml`
2. **Link template** to your Mailcow host: "Mailcow Complete Monitoring v1.0"
3. Wait 5–10 minutes for dashboards to populate

### Verify

```bash
sudo ./test-complete.sh
```

### Force Immediate Data

```bash
systemctl start mailcow-monitor.service    # fresh JSON
systemctl restart zabbix-agent2             # force re-check
```

## File Structure

```
mailcow-monitoring/
├── install.sh                        # Installer (dependency preflight check)
├── uninstall.sh                      # Uninstaller
├── mailcow-zabbix.conf               # 307 UserParameters
├── test-complete.sh                  # Validation script (307 keys)
├── mailcow-monitor.conf              # Sample config → /etc/mailcow-monitor.conf
├── templates/
│   └── mailcow-complete-monitoring.yaml  # Zabbix 7.0 template
├── scripts/
│   ├── mailcow-collector.py          # Main collector (29 modules, SIGTERM handler)
│   ├── mailcow-reader.sh             # JSON reader (Python3-based)
│   ├── mailcow-common.sh             # Shared shell library
│   ├── check_dns.sh                  # DNS (SPF/DKIM/DMARC)
│   ├── check_tls.sh                  # TLS/certificate + SMTP banner
│   ├── check_rbl.sh                  # RBL blacklist check (parallel queries)
│   ├── check_ptr.sh                  # PTR record check
│   ├── check_open_relay.sh           # Open relay check
│   ├── check_security_audit.sh       # DANE/MTA-STS/TLS-RPT/BIMI
│   ├── dovecot_check.sh              # Dovecot stats
│   ├── sync_jobs_check.sh            # IMAP sync jobs
│   ├── postfix_stats_docker.sh       # Postfix queue stats
│   └── postfix_log_analysis.sh       # Postfix logs + Postscreen (single awk pass)
├── mailcow-monitor.service           # systemd oneshot
├── mailcow-monitor.timer             # systemd timer (60s)
├── LICENSE                           # GPLv3
├── MAILCOW-MONITORING-DOKU.md        # Detailed documentation
├── AGENTS.md                         # AI agent guidelines
└── README.md                         # This file
```

## Uninstall

```bash
sudo ./uninstall.sh
```

## License

GPLv3 — code must remain open source and the original author must be credited.
See [LICENSE](LICENSE) for details.

**© 2026 Alexander Fox | PlaNet Fox** — Created with Open Source and ❤
