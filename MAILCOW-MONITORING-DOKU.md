# Mailcow Zabbix Monitoring - Project Documentation

## Version: v1.1 (Date: 2026-04-05)

---

## Architecture (Secure Service Architecture)

```
┌──────────────────────────────┐
│  mailcow-monitor.timer       │  systemd timer, every 60s
│  → mailcow-collector.py      │  runs as ROOT (Python)
│  Collects 307 metrics        │
│  Docker, DB, TLS, DNS, ...   │
│  Writes → JSON files         │
└──────────┬───────────────────┘
           │
     /var/tmp/mailcow-monitor.json          (main cache, 60s)
     /var/tmp/mailcow-monitor-slow.json     (slow cache, 1h)
     /var/tmp/mailcow-monitor-mailflow.json (mailflow cache, 5m)
     /var/tmp/mailcow-monitor-version.json  (version cache, 1h)
           │
┌──────────┴───────────────────┐
│  Zabbix Agent 2              │  runs as ZABBIX
│  307 UserParameters          │
│  → mailcow-reader.sh <key>   │  reads JSON only (Python3)
│  NO Docker, NO sudo          │
└──────────────────────────────┘
```

### Security Model
- Zabbix has **no** Docker access
- **No** UnsafeUserParameters required
- Collector writes world-readable JSON, Reader only reads
- MySQL password passed via `MYSQL_PWD` environment variable (not visible on command line)

### Performance Optimizations
- **Centralized container discovery:** 1× `find_all_containers()` — single `docker ps` instead of 12 individual calls per run
- **ClamAV:** 1 docker exec with shell compound instead of 3-5 individual calls
- **Docker Health:** targeted `docker stats` + 1 batched `docker inspect` instead of N individual calls
- **Slow cache parallelized:** ThreadPoolExecutor (6 threads) for TLS/DNS/RBL checks
- **Mailflow own 5-min cache:** fresh data instead of 1h slow cache
- **shell=False:** `run_cmd()` for simple commands (safer, faster)
- **Parallel RBL DNS lookups:** `check_rbl.sh` runs all 10 queries concurrently (1–2s vs 5–10s)
- **Single `awk` pass:** `postfix_log_analysis.sh` replaced 20 `grep` calls with one `awk` script
- **Time-bounded Nginx errors:** 4xx/5xx counted over fixed 5-minute window (`docker logs --since 5m`)
- **SIGTERM handler:** collector removes `.tmp` files on shutdown

---

## Overview: 307 UserParameters / 29 Collector Modules / 71 Triggers

| # | Module | Items | Triggers | Description |
|---|--------|-------|---------|-------------|
| 1 | Postfix | 16 | 2 | Queue, Connections, Log Events |
| 2 | Postfix Logs | 11 | 1 | SASL, Relay, RBL, TLS, Quota, Virus |
| 3 | Postscreen | 9 | 1 | Connect, Pass, Reject, DNSBL, Pregreet |
| 4 | Dovecot | 10 | 1 | Connections, Login failures, Version |
| 5 | Rspamd | 14 | 1 | Scanned, Spam, Ham, Actions, Detail |
| 6 | Rspamd Bayes | 5 | 1 | Ham/Spam Learned, Ratio, Status |
| 7 | Security | 13 | 3 | Fail2ban, RBL, DNS Records, Open Relay |
| 8 | Security Audit | 6 | 1 | DANE/TLSA, MTA-STS, TLS-RPT, BIMI, Score |
| 9 | Disk | 15 | 2 | Root, Docker, vmail, Log partitions |
| 10 | Inode Usage | 9 | 0 | Root, Docker, Log inode counts |
| 11 | Swap | 4 | 0 | Total, Free, Used, Percent |
| 12 | Sync Jobs | 6 | 0 | Active, Running, Failed, Stuck |
| 13 | Mailbox & Domain | 10 | 0 | Quota, Top 5, Domains |
| 14 | Alias | 5 | 0 | Total, Active, Forwarding |
| 15 | Mailflow (pflogsumm) | 28 | 5 | Received/Delivered/Bounced + Baseline Anomaly |
| 16 | ClamAV | 8 | 3 | Version, Signatures, DB Age |
| 17 | Watchdog | 18 | 2 | 15 Service Health Levels |
| 18 | ACME/Certificate | 7 | 2 | Subject, Issuer, Days Left |
| 19 | Docker Health | 7+LLD | 1 | CPU, RAM, Restarts per Container |
| 20 | SOGo/Memcached | 8 | 1 | Cache Hits, Evictions, Items |
| 21 | SOGo Health | 3 | 0 | Running, Workers, Response Time |
| 22 | Quarantine | 6 | 2 | Total, Spam, Virus, Age, Top Domains |
| 23 | Queue Age | 4 | 2 | Deferred, Active, Hold, Oldest |
| 24 | TLS/SSL | 12 | 4 | Cert Days, HTTPS/IMAPS/Submission, SMTP Banner |
| 25 | MySQL Health | 11 | 0 | Connections, Threads, InnoDB, Slow Queries, DB Size |
| 26 | Redis | 10 | 0 | Memory, Keyspace Hits, Clients, Uptime |
| 27 | Nginx | 8 | 0 | Active Connections, Requests, 4xx/5xx Errors |
| 28 | Unbound DNS | 8 | 0 | Queries, Cache Hit Rate, NXDOMAIN, Memory |
| 29 | System/NTP | 3 | 0 | NTP Sync, Offset, Service |
| 30 | Ratelimit | 3 | 0 | Rate Hits, Exceeded, Outbound Spam |
| 31 | Updates/Version | 12 | 2 | Current, Latest, Commits Behind |
| 32 | Backup | 9 | 3 | Count, Age, Size, Zero Files, Script |
| 33 | Collector | 8 | 2 | Running, Age, Duration, Errors, Module Timing |
| 34 | Agent/Meta | 8 | 2 | Agent Running, Log Errors |
| 35 | LLD Master | 6 | 0 | Discovery JSON for Domains/Mailboxes/Syncjobs |
| | **Total** | **307** | **71** | + 4 LLD Rules, 21 Prototypes, 8 LLD Triggers |

---

## Anomaly Detection (Baseline Triggers)

Instead of fixed thresholds, these triggers automatically learn the normal state:

| Metric | Spike Trigger | Drop Trigger |
|--------|---------------|--------------|
| `mail.received` | >5× weekly average → WARNING | <20% weekly average → HIGH |
| `mail.rejected` | >10× weekly average → WARNING | — |
| `mail.bounced` | >5× weekly average → WARNING | — |
| `mail.deferred` | >5× weekly average → WARNING | — |

All with minimum baseline (e.g. `trendavg > 5`) so fresh installations don't alert immediately. Requires ~1 week of history.

---

## Security Audit Score (0-7)

| Check | Points | Record |
|-------|--------|--------|
| SPF | 1 | `TXT` on domain |
| DKIM | 1 | `TXT` on `dkim._domainkey.domain` |
| DMARC | 1 | `TXT` on `_dmarc.domain` |
| DANE/TLSA | 1 | `TLSA` on `_25._tcp.hostname` |
| MTA-STS | 1 | `TXT` on `_mta-sts.domain` |
| TLS-RPT | 1 | `TXT` on `_smtp._tls.domain` |
| BIMI | 1 | `TXT` on `default._bimi.domain` |

Trigger at Score <3 (WARNING).

---

## Rspamd Bayes Training Status

| Status | Meaning |
|--------|---------|
| `untrained` | 0 messages learned |
| `low` | <200 total learned |
| `unbalanced` | Ham or Spam <50 |
| `good` | 200-999 total, both >50 |
| `excellent` | 1000+ total |

Trigger: INFO when <200 messages learned (if Rspamd has been running >24h).

---

## Postscreen Monitoring

Auto-detected — if Postscreen is not enabled in Postfix, all values remain 0:

| Metric | Description |
|--------|-------------|
| `postscreen.active` | 1=active, 0=not active |
| `postscreen.connect` | Incoming connections |
| `postscreen.pass.new` | New clients, all tests passed |
| `postscreen.pass.old` | Returning (known) clients |
| `postscreen.reject` | Rejected connections |
| `postscreen.dnsbl` | DNSBL hits |
| `postscreen.pregreet` | Bot detection (pregreet failure) |
| `postscreen.hangup` | Disconnects during tests |
| `postscreen.whitelisted` | Whitelisted clients |

Trigger: WARNING at >100 rejects.

---

## LLD (Low-Level Discovery) - 4 Discovery Rules

### Domain Discovery (5 Prototypes, 2 Triggers, 1 Graph)
Per domain automatically: Active, Mailbox count, Used MB, Quota MB, Usage %
Triggers: >80% WARNING, >95% HIGH

### Mailbox Discovery (4 Prototypes, 2 Triggers, 1 Graph)
Per mailbox automatically: Active, Used MB, Quota MB, Usage %
Triggers: >80% WARNING, >95% HIGH

### Sync Job Discovery (5 Prototypes, 2 Triggers)
Per sync job: Active, Running, Success, Age Hours, Exit Status
Triggers: Failed → HIGH, not run in >48h → WARNING

### Docker Container Discovery (7 Prototypes, 2 Triggers, 2 Graphs)
Per container: CPU%, Memory MB/%, Restarts, Uptime, PIDs, Health
Triggers: Restarted → WARNING, Memory >25% → WARNING

---

## 19 Dashboard Pages

| # | Dashboard | Content |
|---|-----------|---------|
| 01 | Postfix | Queue & Connections, Security Events, Mail Problems |
| 02 | TLS Certificates | Cert Days Left per Port |
| 03 | Security | Fail2ban Bans, RBL Status |
| 04 | Rspamd | Spam vs Ham, Spam Rate, Scanned & Learned, Bayes Training |
| 05 | Dovecot | Connections, Login Failures |
| 06 | Disk | Root, Docker, vmail, Log Usage |
| 07 | Backup | Count, Age, Size |
| 08 | Sync Jobs | Active, Running, Failed |
| 09 | Mailboxes | Total, Quota, Top 5 |
| 10 | Mailflow | Volume, Reject Breakdown, Bytes, Warnings |
| 11 | ClamAV | DB Age, Signatures |
| 12 | Watchdog | Overall + Service Health Levels |
| 13 | ACME Certificate | Days Left |
| 14 | Docker Health | CPU Total, Memory Total, Restarts |
| 15 | SOGo/Memcached | Hit Rate, Items, Bytes |
| 16 | Quarantine & Queue | Quarantine, Queue Deferred/Active |
| 17 | Updates | Commits Behind |
| 18 | Agent & Collector | Errors, Data Age |
| 19 | Postscreen | Connections (Connect/Pass), Blocks (Reject/DNSBL/Pregreet) |

---

## Package Files

```
mailcow-monitoring-v1.1/
├── scripts/
│   ├── mailcow-collector.py      # Main collector (29 modules, SIGTERM handler)
│   ├── mailcow-reader.sh         # JSON reader (Python3-based)
│   ├── mailcow-common.sh         # Shared shell library (MySQL helpers)
│   ├── check_rbl.sh              # RBL check (slow cache, parallel DNS queries)
│   ├── check_dns.sh              # DNS SPF/DKIM/DMARC (slow cache)
│   ├── check_tls.sh              # TLS/cert + SMTP banner check (slow cache)
│   ├── check_open_relay.sh       # Open relay check (slow cache)
│   ├── check_ptr.sh              # PTR check (slow cache)
│   ├── check_security_audit.sh   # DANE/MTA-STS/TLS-RPT/BIMI (slow cache)
│   ├── postfix_stats_docker.sh   # Postfix queue stats
│   ├── postfix_log_analysis.sh   # Postfix log + Postscreen (single awk pass)
│   ├── dovecot_check.sh          # Dovecot status
│   └── sync_jobs_check.sh        # Sync job status
├── templates/
│   └── mailcow-complete-monitoring.yaml  # Zabbix 7.0 template
├── mailcow-zabbix.conf           # 307 UserParameters
├── mailcow-monitor.conf          # Sample config → /etc/mailcow-monitor.conf
├── mailcow-monitor.service       # systemd service
├── mailcow-monitor.timer         # systemd timer (60s)
├── install.sh                    # Installer (dependency preflight check)
├── uninstall.sh                  # Uninstaller
├── test-complete.sh              # Test script (307 keys)
├── AGENTS.md                     # AI agent guidelines
├── README.md                     # Quick start guide
├── MAILCOW-MONITORING-DOKU.md    # This documentation
└── LICENSE                       # GPLv3
```

---

## Installation

```bash
# 1. Clone repository
git clone https://github.com/linuser/Mailcow-Zabbix-Monitoring.git
cd Mailcow-Zabbix-Monitoring

# 2. Run installer (checks required/optional dependencies automatically)
sudo ./install.sh

# 3. Import template in Zabbix
#    Data collection → Templates → Import
#    File: templates/mailcow-complete-monitoring.yaml

# 4. Assign template to host
#    Configuration → Hosts → <your-mailcow-host> → Templates → Link

# 5. Test
sudo ./test-complete.sh
```

### Force immediate data after template re-import

```bash
# Run collector immediately (fresh JSON data)
systemctl start mailcow-monitor.service

# Restart Zabbix Agent (forces immediate re-check of all items)
systemctl restart zabbix-agent2
```

---

## Collector Modules (29)

| Module | Data Source | Cache |
|--------|-------------|-------|
| collect_postfix | docker exec, mailq, ss | 60s |
| collect_postfix_logs | postfix_log_analysis.sh | 60s |
| collect_dovecot | dovecot_check.sh | 60s |
| collect_rspamd | Rspamd API :11334 + `rspamc stat` (Bayes) | 60s |
| collect_fail2ban | docker exec, fail2ban-client, nft/iptables | 60s |
| collect_mysql_health | SHOW GLOBAL STATUS/VARIABLES via docker exec | 60s |
| collect_disk | df, du, /proc/meminfo (inode + swap) | 60s |
| collect_sync | sync_jobs_check.sh → MySQL (imapsync) | 60s |
| collect_mailbox | MySQL (mailbox, quota2, domain) | 60s |
| collect_alias | MySQL (alias) | 60s |
| collect_lld | MySQL (domain, mailbox, imapsync) | 60s |
| collect_docker_health | docker stats + docker inspect (batched) | 60s |
| collect_memcached | docker exec → nc 127.0.0.1 11211 | 60s |
| collect_redis | docker exec → redis-cli INFO all | 60s |
| collect_quarantine | MySQL (quarantine) | 60s |
| collect_queue_age | docker exec → find /var/spool/postfix | 60s |
| collect_clamav | docker exec (single compound command) | 60s |
| collect_watchdog | docker logs watchdog (last 10m) | 60s |
| collect_acme | openssl x509 on cert.pem | 60s |
| collect_version | git describe/fetch/rev-list | **1h** |
| collect_meta | systemctl, zabbix_agent2.conf, agent log | 60s |
| collect_backup | Filesystem scan | 60s |
| collect_mailflow | docker logs → pflogsumm | **5m** |
| collect_slow | check_*.sh (parallelized, 6 threads) | **1h** |
| collect_system | timedatectl, chronyc/ntpq | 60s |
| collect_nginx | docker exec → nginx_status + access.log | 60s |
| collect_sogo | docker exec → pgrep + curl response time | 60s |
| collect_unbound | docker exec → unbound-control stats_noreset | 60s |
| collect_ratelimit | MySQL (ratelimit) + watchdog log | 60s |

### Collector Self-Monitoring
- `mailcow.collector.errors` — number of failed modules
- `mailcow.collector.error.detail` — `module:ExceptionType` per error
- `mailcow.collector.module.times` — JSON with runtime per module
- `mailcow.collector.duration` — total runtime in seconds

---

## Known Limitations

- **pflogsumm:** Must be installed on the host (`apt install pflogsumm`)
- **Mailflow:** Only useful on servers with direct mail reception
- **LLD Sync Jobs:** No items if no sync jobs are configured
- **Baseline triggers:** Require ~1 week of history before they work meaningfully
- **Bayes training:** `rspamc stat` requires a running Rspamd container
- **Postscreen:** Values = 0 if Postscreen is not enabled in Postfix (not an error)
- **Security Audit:** DANE/TLSA only on MX hostname, not per domain
- **PTR check / corporate DNS:** If the server uses an internal/corporate DNS that does not have PTR records for public IPs, `check_ptr.sh` will return 0 (false negative). The script uses `@8.8.8.8` as the resolver to avoid this. If `8.8.8.8` is blocked by the corporate firewall, replace it with another public resolver (e.g. `@1.1.1.1`) in `check_ptr.sh`. Also note: the PTR check result is cached for 1 hour in `/var/tmp/ptr_check.cache` — delete this file after any configuration fix to force an immediate re-check.

---

## Changelog

### v1.1 (2026-04-05)

**Performance**
- `find_all_containers()` now uses a single `docker ps` call instead of 12 individual calls (~600–1200ms saved per run)
- `postfix_log_analysis.sh`: replaced 20 `grep` subshells with one `awk` script (single log pass)
- `check_rbl.sh`: all 10 RBL DNS lookups now run in parallel (1–2s vs 5–10s)
- Nginx error counting (`collect_nginx()`) uses `docker logs --since 5m` for a stable 5-minute window

**Installation**
- `install.sh` now has a dependency preflight check: required (`python3`, `docker`) abort install; optional (`dig`, `openssl`, `nc`, `pflogsumm`, `jq`) warn but continue
- Fixed incorrect "246 UserParameters" string in installer output → "307 UserParameters"

**Architecture**
- Added SIGTERM handler in `mailcow-collector.py`: cleans up all `.tmp` files on shutdown
- Architecture diagram updated to show 4 separate cache files (added `mailcow-monitor-version.json`)

**Bug Fixes**
- `check_ptr.sh`: PTR lookup now uses `@8.8.8.8` as explicit resolver — fixes false negatives on servers with internal/corporate DNS that does not forward PTR queries for public IPs

**Monitoring**
- Quarantine SQL reduced from 3 queries to 2 (COUNT/age + spam/virus combined into one query)

### v1.0 (2026-02-18)

Initial release: 307 UserParameters, 29 collector modules, 71 triggers, 19 dashboards.

---

## License

**GPLv3** — This code must remain open source. When using, modifying or distributing, the original author must be credited.

© 2026 Alexander Fox | PlaNet Fox — https://github.com/linuser/Mailcow-Zabbix-Monitoring

Created with Open Source and ❤
