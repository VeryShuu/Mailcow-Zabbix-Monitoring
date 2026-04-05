#!/usr/bin/env python3
# ====================================================================
#  Mailcow Zabbix Monitoring - Collector
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Collects 307 metrics from 29 modules (Docker, MySQL, DNS,
#               TLS, Rspamd, ClamAV, Redis, Nginx, Unbound, SOGo, etc.) into JSON
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
"""
Mailcow Monitoring Collector v1.0
Collects all metrics into a JSON file.
Runs as systemd service (root) — no Docker/sudo required for Zabbix.
"""

import json
import os
import re
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# ====================================================================
# CONFIGURATION
# ====================================================================

def _read_monitor_conf():
    """Read /etc/mailcow-monitor.conf and return config dict."""
    conf = {
        "MAILCOW_DIR": "/opt/mailcow-dockerized",
        "BACKUP_PATH": "",
        "SKIP_GIT_FETCH": "false",
    }
    try:
        with open("/etc/mailcow-monitor.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key in conf and val:
                    conf[key] = val
    except FileNotFoundError:
        pass
    return conf

_MONITOR_CONF = _read_monitor_conf()
MAILCOW_DIR = _MONITOR_CONF["MAILCOW_DIR"]
OUTPUT = "/var/tmp/mailcow-monitor.json"
OUTPUT_TMP = OUTPUT + ".tmp"
SLOW_CACHE = "/var/tmp/mailcow-monitor-slow.json"
SLOW_MAX_AGE = 3600  # seconds
MAILFLOW_CACHE = "/var/tmp/mailcow-monitor-mailflow.json"
MAILFLOW_MAX_AGE = 300  # 5 minutes
VERSION_CACHE = "/var/tmp/mailcow-monitor-version.json"
VERSION_MAX_AGE = 3600  # git fetch once per hour

# ====================================================================
# SIGNAL HANDLING (A2)
# ====================================================================

_TMP_FILES = [
    OUTPUT_TMP,
    SLOW_CACHE + ".tmp",
    MAILFLOW_CACHE + ".tmp",
    VERSION_CACHE + ".tmp",
]


def _cleanup_handler(signum, frame):
    try:
        for f in _TMP_FILES:
            if os.path.exists(f):
                os.unlink(f)
    except Exception:
        pass
    sys.exit(0)


signal.signal(signal.SIGTERM, _cleanup_handler)

# ====================================================================
# HELPER FUNCTIONS
# ====================================================================

def now():
    return int(time.time())


def run(cmd, timeout=30, default=""):
    """Execute shell command, return default on error."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else default
    except (subprocess.TimeoutExpired, Exception):
        return default


def run_cmd(args, timeout=30, default=""):
    """Execute command as list (no shell=True, safer & faster)."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else default
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return default


def run_int(cmd, timeout=30, default=0):
    """Execute shell command, return result as int."""
    val = run(cmd, timeout, str(default))
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def docker_exec(container, cmd, timeout=15, default=""):
    """Execute command in Docker container."""
    if not container:
        return default
    return run(f'docker exec "{container}" {cmd}', timeout, default)


def docker_exec_int(container, cmd, timeout=15, default=0):
    """Execute command in Docker container, return result as int."""
    val = docker_exec(container, cmd, timeout, str(default))
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def mysql_exec(container, dbpass, sql, timeout=15, default=""):
    """MySQL query via docker exec using MYSQL_PWD (password not on command line)."""
    if not container or not dbpass:
        return default
    return run_cmd(
        ["docker", "exec", "-e", f"MYSQL_PWD={dbpass}", container,
         "mysql", "-u", "mailcow", "mailcow", "-Nse", sql],
        timeout=timeout, default=default)


def mysql_root_exec(container, dbroot, sql, timeout=15, default=""):
    """MySQL query via docker exec as root (for SHOW GLOBAL STATUS / SHOW VARIABLES)."""
    if not container or not dbroot:
        return default
    return run_cmd(
        ["docker", "exec", "-e", f"MYSQL_PWD={dbroot}", container,
         "mysql", "-u", "root", "-Nse", sql],
        timeout=timeout, default=default)


def read_config():
    """Read Mailcow configuration."""
    conf_path = os.path.join(MAILCOW_DIR, "mailcow.conf")
    config = {"hostname": "", "dbpass": "", "dbroot": "", "timezone": "unknown"}
    try:
        with open(conf_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("MAILCOW_HOSTNAME="):
                    config["hostname"] = line.split("=", 1)[1].strip()
                elif line.startswith("DBPASS="):
                    config["dbpass"] = line.split("=", 1)[1].strip()
                elif line.startswith("DBROOT="):
                    config["dbroot"] = line.split("=", 1)[1].strip()
                elif line.startswith("TZ="):
                    config["timezone"] = line.split("=", 1)[1].strip()
    except FileNotFoundError:
        pass
    return config


def find_container(name_filter):
    """Find Docker container by name fragment."""
    out = run_cmd(
        ["docker", "ps", "--filter", f"name={name_filter}", "--format", "{{.Names}}"],
        timeout=10)
    for line in out.splitlines():
        if "mailcow" in line.lower():
            return line.strip()
    return ""


def find_all_containers():
    """Find all Mailcow containers in one docker ps call (P2: single call instead of 12)."""
    out = run_cmd(
        ["docker", "ps", "--filter", "name=mailcow", "--format", "{{.Names}}"],
        timeout=10)
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    service_names = ["postfix", "dovecot", "rspamd", "netfilter", "clamd",
                     "watchdog", "memcached", "redis", "nginx", "sogo", "unbound"]
    containers = {name: "" for name in service_names}
    containers["mysql"] = ""
    for line in lines:
        lower = line.lower()
        for name in service_names:
            if name in lower and not containers[name]:
                containers[name] = line
        if not containers["mysql"] and ("mysql" in lower or "maria" in lower):
            containers["mysql"] = line
    return containers


def _read_json_cache(cache_file, max_age, refresh_cmd):
    """Read JSON cache file, refreshing via one shell call if stale (P3)."""
    try:
        age = now() - int(os.path.getmtime(cache_file))
    except OSError:
        age = max_age + 1
    if age > max_age:
        run(f"{refresh_cmd} 2>/dev/null", timeout=30)
    try:
        with open(cache_file) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


# ====================================================================
# COLLECTOR MODULES
# ====================================================================

def collect_postfix(container):
    """Collect Postfix metrics."""
    data = {
        "postfix.process.running": 0,
        "postfix.pfmailq": 0,
        "postfix.connections": 0,
        "mailcow.queue.disk": 0,
        "mailcow.container.version.postfix": "unknown",
    }
    if not container:
        return data

    # Process check
    pid = docker_exec(container, "cat /var/spool/postfix/pid/master.pid 2>/dev/null").strip()
    if pid:
        check = docker_exec(container, f"test -d /proc/{pid} && echo 1 || echo 0")
        data["postfix.process.running"] = 1 if check == "1" else 0

    # Queue size — match Postfix queue IDs: hex chars (A-F0-9) or long alphanumeric IDs
    mq = docker_exec(container, 'mailq 2>/dev/null')
    data["postfix.pfmailq"] = len([l for l in mq.splitlines()
                                   if l and re.match(r'^[A-F0-9]{6,}|^[A-Za-z0-9]{15,}', l)])

    # Connections
    conn_count = docker_exec_int(container,
        "sh -c \"ss -tn state established '( dport = :25 or sport = :25 )' 2>/dev/null | tail -n +2 | wc -l\"")
    data["postfix.connections"] = max(0, conn_count)

    # Queue disk usage
    df_out = docker_exec(container, "df /var/spool/postfix 2>/dev/null")
    for line in df_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            data["mailcow.queue.disk"] = int(parts[4].replace("%", ""))
            break

    # Postfix version
    ver = docker_exec(container, "postconf mail_version 2>/dev/null")
    if ver and "=" in ver:
        data["mailcow.container.version.postfix"] = ver.split()[-1]

    return data


def collect_postfix_logs():
    """Collect Postfix log statistics (P3: read cache directly, one refresh call max)."""
    data = {
        "postfix.fetch_log_data": run("/usr/local/bin/postfix_stats_docker.sh 2>/dev/null"),
    }
    cache = _read_json_cache(
        "/var/tmp/postfix_log_analysis.cache", 60,
        "/usr/local/bin/postfix_log_analysis.sh sasl_auth_failed")
    log_keys = [
        ("postfix.log.sasl.auth.failed", "sasl_auth_failed"),
        ("postfix.log.relay.denied", "relay_denied"),
        ("postfix.log.spam.rejected", "spam_rejected"),
        ("postfix.log.rbl.reject", "rbl_reject"),
        ("postfix.log.user.unknown", "user_unknown"),
        ("postfix.log.connection.timeout", "connection_timeout"),
        ("postfix.log.tls.failed", "tls_failed"),
        ("postfix.log.quota.exceeded", "quota_exceeded"),
        ("postfix.log.virus.found", "virus_found"),
        ("postfix.log.warnings", "warnings"),
        ("postfix.log.errors", "errors"),
        ("postfix.postscreen.active", "postscreen_active"),
        ("postfix.postscreen.pass.new", "postscreen_pass_new"),
        ("postfix.postscreen.pass.old", "postscreen_pass_old"),
        ("postfix.postscreen.reject", "postscreen_reject"),
        ("postfix.postscreen.dnsbl", "postscreen_dnsbl"),
        ("postfix.postscreen.pregreet", "postscreen_pregreet"),
        ("postfix.postscreen.hangup", "postscreen_hangup"),
        ("postfix.postscreen.whitelisted", "postscreen_whitelisted"),
        ("postfix.postscreen.connect", "postscreen_connect"),
    ]
    for json_key, cache_key in log_keys:
        try:
            data[json_key] = int(cache.get(cache_key, 0))
        except (ValueError, TypeError):
            data[json_key] = 0
    return data


def collect_dovecot(container):
    """Collect Dovecot metrics (P3: log-based metrics from cache, live metrics via docker exec)."""
    data = {
        "mailcow.dovecot.running": 0,
        "mailcow.dovecot.connections": 0,
        "mailcow.dovecot.version": "unknown",
        "mailcow.dovecot.imap.errors": 0,
        "mailcow.dovecot.imap.login.failed": 0,
        "mailcow.dovecot.pop3.login.failed": 0,
        "mailcow.dovecot.imap.disconnected": 0,
        "mailcow.dovecot.quota.warnings": 0,
        "mailcow.dovecot.sync.errors": 0,
        "mailcow.container.version.dovecot": "unknown",
    }
    if not container:
        return data

    data["mailcow.dovecot.running"] = 1

    conn_out = docker_exec(container, "doveadm who 2>/dev/null | wc -l", timeout=10)
    try:
        data["mailcow.dovecot.connections"] = max(0, int(conn_out.strip()))
    except (ValueError, TypeError):
        pass

    version = docker_exec(container, "dovecot --version 2>/dev/null | awk '{print $1}'", timeout=5)
    if version:
        data["mailcow.dovecot.version"] = version
        data["mailcow.container.version.dovecot"] = version

    cache = _read_json_cache(
        "/var/tmp/dovecot_check.cache", 60,
        "/usr/local/bin/dovecot_check.sh imap_login_failed")
    cache_keys = [
        ("mailcow.dovecot.imap.errors", "imap_errors"),
        ("mailcow.dovecot.imap.login.failed", "imap_login_failed"),
        ("mailcow.dovecot.pop3.login.failed", "pop3_login_failed"),
        ("mailcow.dovecot.imap.disconnected", "imap_disconnected"),
        ("mailcow.dovecot.quota.warnings", "quota_warnings"),
        ("mailcow.dovecot.sync.errors", "sync_errors"),
    ]
    for data_key, cache_key in cache_keys:
        try:
            data[data_key] = int(cache.get(cache_key, 0))
        except (ValueError, TypeError):
            pass

    return data


def collect_rspamd(container):
    """Collect Rspamd metrics (including action details + Bayes training)."""
    data = {
        "mailcow.rspamd.running": 0,
        "mailcow.rspamd.scanned": 0,
        "mailcow.rspamd.spam": 0,
        "mailcow.rspamd.ham": 0,
        "mailcow.rspamd.greylist": 0,
        "mailcow.rspamd.soft_reject": 0,
        "mailcow.rspamd.rewrite": 0,
        "mailcow.rspamd.learned": 0,
        "mailcow.rspamd.spam.rate": 0,
        "mailcow.rspamd.uptime": 0,
        "mailcow.rspamd.version": "unknown",
        "mailcow.rspamd.add.header": 0,
        "mailcow.rspamd.reject.total": 0,
        "mailcow.rspamd.action.detail": "-",
        # Bayes Training (#5 Roadmap)
        "mailcow.rspamd.bayes.ham.learned": 0,
        "mailcow.rspamd.bayes.spam.learned": 0,
        "mailcow.rspamd.bayes.total.learned": 0,
        "mailcow.rspamd.bayes.ratio": 0,
        "mailcow.rspamd.bayes.status": "unknown",
    }
    if not container:
        return data

    raw = docker_exec(container, "wget -q -O - --timeout=5 http://localhost:11334/stat 2>/dev/null")
    if not raw:
        return data

    data["mailcow.rspamd.running"] = 1

    try:
        stat = json.loads(raw)
    except json.JSONDecodeError:
        return data

    actions = stat.get("actions", {})
    scanned = stat.get("scanned", 0)

    data["mailcow.rspamd.scanned"] = scanned
    data["mailcow.rspamd.spam"] = actions.get("reject", 0)
    data["mailcow.rspamd.ham"] = actions.get("no action", 0)
    data["mailcow.rspamd.greylist"] = actions.get("greylist", 0)
    data["mailcow.rspamd.soft_reject"] = actions.get("soft reject", 0)
    data["mailcow.rspamd.rewrite"] = actions.get("rewrite subject", 0)
    data["mailcow.rspamd.learned"] = stat.get("learned", 0)
    data["mailcow.rspamd.uptime"] = stat.get("uptime", 0)
    data["mailcow.rspamd.version"] = stat.get("version", "unknown")

    if scanned > 0:
        spam_total = actions.get("reject", 0) + actions.get("add header", 0)
        data["mailcow.rspamd.spam.rate"] = round(spam_total * 100 / scanned, 1)

    # Detail actions
    data["mailcow.rspamd.add.header"] = actions.get("add header", 0)
    data["mailcow.rspamd.reject.total"] = actions.get("reject", 0)

    parts = []
    for act_name, act_count in actions.items():
        if act_count > 0:
            parts.append(f'{act_name.replace(" ", "_")}:{act_count}')
    data["mailcow.rspamd.action.detail"] = ",".join(parts) if parts else "-"

    # --- Bayes Training Stats via rspamc stat ---
    bayes_raw = docker_exec(container, "rspamc stat 2>/dev/null", timeout=10)
    if bayes_raw:
        ham_learned = 0
        spam_learned = 0
        current_statfile = ""
        for line in bayes_raw.splitlines():
            line_s = line.strip()
            if "BAYES_HAM" in line_s:
                current_statfile = "ham"
            elif "BAYES_SPAM" in line_s:
                current_statfile = "spam"
            elif line_s.startswith("learned:") or line_s.startswith("Learned:"):
                try:
                    val = int(line_s.split(":")[1].strip())
                    if current_statfile == "ham":
                        ham_learned = val
                    elif current_statfile == "spam":
                        spam_learned = val
                except (ValueError, IndexError):
                    pass

        total = ham_learned + spam_learned
        data["mailcow.rspamd.bayes.ham.learned"] = ham_learned
        data["mailcow.rspamd.bayes.spam.learned"] = spam_learned
        data["mailcow.rspamd.bayes.total.learned"] = total

        if total > 0:
            data["mailcow.rspamd.bayes.ratio"] = round(ham_learned * 100 / total, 1)

        # Status: untrained / low / good / excellent
        if total == 0:
            data["mailcow.rspamd.bayes.status"] = "untrained"
        elif total < 200:
            data["mailcow.rspamd.bayes.status"] = "low"
        elif ham_learned < 50 or spam_learned < 50:
            data["mailcow.rspamd.bayes.status"] = "unbalanced"
        elif total < 1000:
            data["mailcow.rspamd.bayes.status"] = "good"
        else:
            data["mailcow.rspamd.bayes.status"] = "excellent"

    return data


def collect_fail2ban(container):
    """Collect Fail2ban/Netfilter metrics."""
    data = {
        "mailcow.security.fail2ban.banned": 0,
        "mailcow.security.fail2ban.postfix": 0,
        "mailcow.security.fail2ban.dovecot": 0,
        "mailcow.security.fail2ban.sogo": 0,
    }
    if not container:
        return data

    # Per-service bans via fail2ban-client (works with both iptables and nftables)
    per_service_total = 0
    for service, key in [("postfix-sasl", "postfix"), ("dovecot", "dovecot"), ("sogo-auth", "sogo")]:
        out = docker_exec(container, f"fail2ban-client status {service} 2>/dev/null")
        for line in out.splitlines():
            if "Currently banned" in line:
                match = re.search(r"(\d+)", line)
                if match:
                    count = int(match.group(1))
                    data[f"mailcow.security.fail2ban.{key}"] = count
                    per_service_total += count
                break

    # Total bans: detect nftables vs iptables, fall back to per-service sum
    nft_out = docker_exec(container, "nft list ruleset 2>/dev/null")
    if "MAILCOW" in nft_out:
        nft_count = sum(1 for l in nft_out.splitlines()
                        if "ip saddr" in l and "drop" in l.lower())
        data["mailcow.security.fail2ban.banned"] = nft_count if nft_count > 0 else per_service_total
    else:
        ipt = docker_exec(container, "iptables -L MAILCOW -n 2>/dev/null")
        banned = len([l for l in ipt.splitlines() if "DROP" in l])
        data["mailcow.security.fail2ban.banned"] = banned if banned > 0 else per_service_total

    return data


def collect_mysql_health(container, dbroot, dbpass):
    """Collect MySQL/MariaDB health metrics."""
    data = {
        "mailcow.mysql.connections.current": 0,
        "mailcow.mysql.connections.max": 0,
        "mailcow.mysql.connections.pct": 0,
        "mailcow.mysql.threads.running": 0,
        "mailcow.mysql.threads.connected": 0,
        "mailcow.mysql.slow.queries": 0,
        "mailcow.mysql.innodb.hit.rate": 0,
        "mailcow.mysql.innodb.buffer.used.pct": 0,
        "mailcow.mysql.uptime": 0,
        "mailcow.mysql.db.size.mb": 0,
        "mailcow.mysql.running": 0,
    }

    if not container:
        return data

    status_out = mysql_root_exec(container, dbroot,
        "SHOW GLOBAL STATUS", timeout=15)
    if not status_out:
        status_out = mysql_exec(container, dbpass,
            "SHOW GLOBAL STATUS", timeout=15)
    if not status_out:
        return data

    status = {}
    for line in status_out.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2:
            status[parts[0]] = parts[1]

    vars_out = mysql_root_exec(container, dbroot,
        "SHOW GLOBAL VARIABLES LIKE 'max_connections'", timeout=10)
    if not vars_out:
        vars_out = mysql_exec(container, dbpass,
            "SHOW GLOBAL VARIABLES LIKE 'max_connections'", timeout=10)

    max_conn = 151
    for line in (vars_out or "").splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2 and parts[0] == "max_connections":
            try:
                max_conn = int(parts[1])
            except ValueError:
                pass

    def si(key, default=0):
        try:
            return int(status.get(key, default))
        except (ValueError, TypeError):
            return default

    threads_connected = si("Threads_connected")
    threads_running = si("Threads_running")
    slow_queries = si("Slow_queries")
    uptime = si("Uptime")

    buf_read_req = si("Innodb_buffer_pool_read_requests")
    buf_reads = si("Innodb_buffer_pool_reads")
    if buf_read_req > 0:
        hit_rate = round((buf_read_req - buf_reads) / buf_read_req * 100, 1)
    else:
        hit_rate = 0

    buf_pages_total = si("Innodb_buffer_pool_pages_total")
    buf_pages_data = si("Innodb_buffer_pool_pages_data")
    if buf_pages_total > 0:
        buf_used_pct = round(buf_pages_data / buf_pages_total * 100, 1)
    else:
        buf_used_pct = 0

    conn_pct = round(threads_connected / max_conn * 100, 1) if max_conn > 0 else 0

    db_size_out = mysql_exec(container, dbpass,
        "SELECT ROUND(SUM(data_length+index_length)/1024/1024,2) "
        "FROM information_schema.tables WHERE table_schema='mailcow'",
        timeout=10)
    try:
        db_size = round(float(db_size_out), 2)
    except (ValueError, TypeError):
        db_size = 0

    data.update({
        "mailcow.mysql.connections.current": threads_connected,
        "mailcow.mysql.connections.max": max_conn,
        "mailcow.mysql.connections.pct": conn_pct,
        "mailcow.mysql.threads.running": threads_running,
        "mailcow.mysql.threads.connected": threads_connected,
        "mailcow.mysql.slow.queries": slow_queries,
        "mailcow.mysql.innodb.hit.rate": hit_rate,
        "mailcow.mysql.innodb.buffer.used.pct": buf_used_pct,
        "mailcow.mysql.uptime": uptime,
        "mailcow.mysql.db.size.mb": db_size,
        "mailcow.mysql.running": 1,
    })
    return data


def collect_disk(dovecot_container):
    """Collect disk metrics."""
    data = {}

    # Local partitions
    for mount, prefix in [("/", "root"), ("/var/lib/docker", "docker"), ("/var/log", "log")]:
        data[f"mailcow.disk.{prefix}.total"] = 0
        data[f"mailcow.disk.{prefix}.free"] = 0
        data[f"mailcow.disk.{prefix}.used"] = 0
        df_out = run(f"df {mount} 2>/dev/null")
        lines = df_out.splitlines()
        if len(lines) >= 2:
            parts = lines[-1].split()
            if len(parts) >= 5:
                data[f"mailcow.disk.{prefix}.total"] = int(parts[1])
                data[f"mailcow.disk.{prefix}.free"] = int(parts[3])
                data[f"mailcow.disk.{prefix}.used"] = int(parts[4].replace("%", ""))

    # Docker top containers
    top = run("docker ps --format 'table {{.Names}}\t{{.Size}}' 2>/dev/null")
    lines = top.splitlines()[1:6]  # First 5 containers
    data["mailcow.disk.docker.top.containers"] = ",".join(lines) if lines else "N/A"

    # vmail
    data["mailcow.disk.vmail.exists"] = 0
    data["mailcow.disk.vmail.total"] = 0
    data["mailcow.disk.vmail.free"] = 0
    data["mailcow.disk.vmail.used"] = 0
    data["mailcow.disk.vmail.maildir.size"] = 0

    if dovecot_container:
        exists = docker_exec(dovecot_container, "test -d /var/vmail && echo 1 || echo 0")
        if exists == "1":
            data["mailcow.disk.vmail.exists"] = 1
            df_out = docker_exec(dovecot_container, "df /var/vmail 2>/dev/null")
            lines = df_out.splitlines()
            if len(lines) >= 2:
                parts = lines[-1].split()
                if len(parts) >= 5:
                    data["mailcow.disk.vmail.total"] = int(parts[1])
                    data["mailcow.disk.vmail.free"] = int(parts[3])
                    data["mailcow.disk.vmail.used"] = int(parts[4].replace("%", ""))
            data["mailcow.disk.vmail.maildir.size"] = docker_exec_int(
                dovecot_container, "du -sm /var/vmail 2>/dev/null | cut -f1")

    # Inode usage for critical mount points
    for mount, prefix in [("/", "root"), ("/var/lib/docker", "docker"), ("/var/log", "log")]:
        data[f"mailcow.disk.{prefix}.inodes.total"] = 0
        data[f"mailcow.disk.{prefix}.inodes.free"] = 0
        data[f"mailcow.disk.{prefix}.inodes.used"] = 0
        dfi_out = run(f"df -i {mount} 2>/dev/null")
        lines = dfi_out.splitlines()
        if len(lines) >= 2:
            parts = lines[-1].split()
            if len(parts) >= 5:
                try:
                    data[f"mailcow.disk.{prefix}.inodes.total"] = int(parts[1])
                    data[f"mailcow.disk.{prefix}.inodes.free"] = int(parts[3])
                    used_str = parts[4].replace("%", "")
                    data[f"mailcow.disk.{prefix}.inodes.used"] = int(used_str) if used_str != "-" else 0
                except (ValueError, IndexError):
                    pass

    # Swap usage
    data["mailcow.swap.total"] = 0
    data["mailcow.swap.free"] = 0
    data["mailcow.swap.used"] = 0
    data["mailcow.swap.used.pct"] = 0
    try:
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
        swap_total = meminfo.get("SwapTotal", 0)
        swap_free = meminfo.get("SwapFree", 0)
        swap_used = swap_total - swap_free
        data["mailcow.swap.total"] = swap_total
        data["mailcow.swap.free"] = swap_free
        data["mailcow.swap.used"] = swap_used
        if swap_total > 0:
            data["mailcow.swap.used.pct"] = round(swap_used / swap_total * 100, 1)
    except (OSError, ValueError):
        pass

    return data


def collect_sync(mysql_container, dbpass):
    """Collect sync job metrics (P3: direct MySQL instead of 6 shell calls)."""
    data = {f"mailcow.sync.jobs.{k}": 0
            for k in ["active", "running", "failed", "stuck", "never_run", "oldest_run"]}
    if not mysql_container or not dbpass:
        return data
    result = mysql_exec(mysql_container, dbpass,
        "SELECT "
        "COALESCE(SUM(active=1), 0), "
        "COALESCE(SUM(is_running=1), 0), "
        "COALESCE(SUM((returned_text LIKE '%error%' OR returned_text LIKE '%fail%' OR returned_text LIKE '%died%') AND last_run > DATE_SUB(NOW(), INTERVAL 24 HOUR)), 0), "
        "COALESCE(SUM(is_running=1 AND last_run < DATE_SUB(NOW(), INTERVAL 24 HOUR)), 0), "
        "COALESCE(SUM(active=1 AND last_run IS NULL), 0), "
        "COALESCE(TIMESTAMPDIFF(HOUR, MAX(CASE WHEN active=1 AND last_run IS NOT NULL THEN last_run END), NOW()), 0) "
        "FROM imapsync",
        timeout=10)
    if result:
        for line in result.splitlines():
            parts = line.split('\t')
            if len(parts) >= 6:
                keys = ["active", "running", "failed", "stuck", "never_run", "oldest_run"]
                for i, key in enumerate(keys):
                    try:
                        data[f"mailcow.sync.jobs.{key}"] = int(float(parts[i] or 0))
                    except (ValueError, TypeError):
                        pass
    return data


def collect_mailbox(mysql_container, dbpass):
    """Collect mailbox metrics."""
    data = {
        "mailcow.mailbox.total": 0,
        "mailcow.mailbox.active": 0,
        "mailcow.mailbox.quota.used.total": 0,
        "mailcow.mailbox.over.quota": 0,
        "mailcow.mailbox.unlimited": 0,
        "mailcow.mailbox.top5": "-",
        "mailcow.mailbox.over.detail": "-",
        "mailcow.domain.total": 0,
        "mailcow.domain.active": 0,
        "mailcow.domain.list": "-",
    }
    if not mysql_container or not dbpass:
        return data

    # Query domains
    dom_raw = mysql_exec(mysql_container, dbpass,
        "SELECT domain, active FROM domain", timeout=10)
    if dom_raw:
        domains = []
        for line in dom_raw.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                domains.append({"domain": parts[0], "active": int(parts[1])})
        data["mailcow.domain.total"] = len(domains)
        data["mailcow.domain.active"] = sum(1 for d in domains if d["active"] == 1)
        active_list = [d["domain"] for d in domains if d["active"] == 1]
        data["mailcow.domain.list"] = ",".join(active_list) if active_list else "-"

    # Query mailboxes

    sql = ("SELECT m.username, m.quota, m.active, COALESCE(q.bytes,0) "
           "FROM mailbox m LEFT JOIN quota2 q ON m.username=q.username "
           "WHERE m.kind='' OR m.kind IS NULL")
    raw = mysql_exec(mysql_container, dbpass, sql, timeout=20)
    if not raw:
        return data

    mailboxes = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4:
            try:
                mailboxes.append({
                    "user": parts[0],
                    "quota": int(parts[1]),
                    "active": int(parts[2]),
                    "used": int(parts[3]),
                })
            except ValueError:
                continue

    if not mailboxes:
        return data

    data["mailcow.mailbox.total"] = len(mailboxes)
    data["mailcow.mailbox.active"] = sum(1 for m in mailboxes if m["active"] == 1)
    data["mailcow.mailbox.quota.used.total"] = sum(m["used"] for m in mailboxes) // 1048576
    data["mailcow.mailbox.unlimited"] = sum(1 for m in mailboxes if m["active"] == 1 and m["quota"] == 0)

    # Over 80% quota
    over = []
    for m in mailboxes:
        if m["active"] == 1 and m["quota"] > 0:
            pct = m["used"] * 100 // m["quota"]
            if pct >= 80:
                over.append(f'{m["user"]}:{pct}%')
    data["mailcow.mailbox.over.quota"] = len(over)
    data["mailcow.mailbox.over.detail"] = ",".join(over) if over else "-"

    # Top 5 largest
    by_size = sorted(mailboxes, key=lambda m: m["used"], reverse=True)[:5]
    data["mailcow.mailbox.top5"] = ",".join(
        f'{m["user"]}:{m["used"] // 1048576}MB' for m in by_size)

    return data


def collect_clamav(container):
    """Collect ClamAV/antivirus metrics — 1 docker exec instead of 3-5 (#5)."""
    data = {
        "mailcow.clamav.running": 0,
        "mailcow.clamav.version": "unknown",
        "mailcow.clamav.signatures": 0,
        "mailcow.clamav.daily.version": 0,
        "mailcow.clamav.daily.age": 999,
        "mailcow.clamav.daily.build": "unknown",
        "mailcow.clamav.main.version": 0,
        "mailcow.clamav.db.size": 0,
    }

    if not container:
        return data

    # Single docker exec for all ClamAV info
    combined = docker_exec(container, 'sh -c "'
        'echo ===VERSION===; clamscan --version 2>/dev/null; '
        'echo ===DAILY===; '
        'sigtool --info /var/lib/clamav/daily.cvd 2>/dev/null || '
        'sigtool --info /var/lib/clamav/daily.cld 2>/dev/null; '
        'echo ===MAIN===; '
        'sigtool --info /var/lib/clamav/main.cvd 2>/dev/null || '
        'sigtool --info /var/lib/clamav/main.cld 2>/dev/null; '
        'echo ===DBSIZE===; du -sm /var/lib/clamav 2>/dev/null'
        '"', timeout=20)

    if not combined:
        return data

    data["mailcow.clamav.running"] = 1

    section = ""
    for line in combined.splitlines():
        if line.startswith("===") and line.endswith("==="):
            section = line.strip("=")
            continue

        if section == "VERSION" and line.strip():
            parts = line.split("/")
            if parts:
                data["mailcow.clamav.version"] = parts[0].replace("ClamAV ", "").strip()

        elif section in ("DAILY", "MAIN"):
            if line.startswith("Version:"):
                try:
                    ver = int(line.split(":")[1].strip())
                    if section == "DAILY":
                        data["mailcow.clamav.daily.version"] = ver
                    else:
                        data["mailcow.clamav.main.version"] = ver
                except ValueError:
                    pass
            elif line.startswith("Signatures:"):
                try:
                    data["mailcow.clamav.signatures"] += int(line.split(":")[1].strip())
                except ValueError:
                    pass
            elif section == "DAILY" and line.startswith("Build time:"):
                build_str = line.split(":", 1)[1].strip()
                data["mailcow.clamav.daily.build"] = build_str
                for fmt in ["%d %b %Y %H:%M %z", "%d %b %Y %H:%M:%S %z"]:
                    try:
                        build_dt = datetime.strptime(build_str, fmt)
                        data["mailcow.clamav.daily.age"] = (datetime.now(timezone.utc) - build_dt).days
                        break
                    except ValueError:
                        continue

        elif section == "DBSIZE" and line.strip():
            try:
                data["mailcow.clamav.db.size"] = int(line.split()[0])
            except (ValueError, IndexError):
                pass

    return data


def collect_watchdog(container):
    """Collect Mailcow Watchdog health data from container logs."""
    # Services monitored by the watchdog
    services = {
        "Postfix": "mailcow.watchdog.postfix",
        "Dovecot": "mailcow.watchdog.dovecot",
        "Rspamd": "mailcow.watchdog.rspamd",
        "MySQL/MariaDB": "mailcow.watchdog.mysql",
        "Nginx": "mailcow.watchdog.nginx",
        "SOGo": "mailcow.watchdog.sogo",
        "Redis": "mailcow.watchdog.redis",
        "Unbound": "mailcow.watchdog.unbound",
        "PHP-FPM": "mailcow.watchdog.phpfpm",
        "Fail2ban": "mailcow.watchdog.fail2ban",
        "ACME": "mailcow.watchdog.acme",
        "Mail queue": "mailcow.watchdog.queue",
        "Olefy": "mailcow.watchdog.olefy",
        "Dovecot replication": "mailcow.watchdog.replication",
        "Ratelimit": "mailcow.watchdog.ratelimit",
    }

    data = {}
    for svc, key in services.items():
        data[key] = 0  # 0 = no data / not checked

    data["mailcow.watchdog.overall"] = 999  # 999 = no-data sentinel (watchdog quiet / no logs)
    data["mailcow.watchdog.unhealthy"] = 0
    data["mailcow.watchdog.detail"] = "-"

    if not container:
        return data

    # Parse last 10 minutes of watchdog logs (watchdog checks every ~5min)
    raw = run(f'docker logs --since 10m "{container}" 2>&1', timeout=15)
    if not raw:
        return data

    # Extract last health level per service
    # Format: "Postfix health level: 100% (8/8), health trend: 0"
    seen = set()
    for line in raw.splitlines():
        for svc, key in services.items():
            if svc + " health level:" in line:
                m = re.search(r'health level: (\d+)%', line)
                if m:
                    data[key] = int(m.group(1))
                    seen.add(key)

    # Calculate overall + count unhealthy
    levels = []
    unhealthy = []
    for svc, key in services.items():
        if key in seen:
            levels.append(data[key])
            if data[key] < 100:
                unhealthy.append(f"{svc}:{data[key]}%")
    if levels:
        data["mailcow.watchdog.overall"] = min(levels)
    data["mailcow.watchdog.unhealthy"] = len(unhealthy)
    data["mailcow.watchdog.detail"] = ",".join(unhealthy) if unhealthy else "-"

    return data




def collect_acme():
    """Collect ACME/Let's Encrypt certificate metrics."""
    data = {
        "mailcow.acme.cert.exists": 0,
        "mailcow.acme.cert.subject": "unknown",
        "mailcow.acme.cert.issuer": "unknown",
        "mailcow.acme.cert.valid.from": "unknown",
        "mailcow.acme.cert.valid.until": "unknown",
        "mailcow.acme.cert.days.left": 0,
        "mailcow.acme.cert.serial": "unknown",
    }

    cert_path = os.path.join(MAILCOW_DIR, "data/assets/ssl/cert.pem")
    if not os.path.isfile(cert_path):
        return data

    data["mailcow.acme.cert.exists"] = 1

    # Certificate subject
    subj = run(f'openssl x509 -in "{cert_path}" -noout -subject 2>/dev/null')
    if subj:
        # "subject=CN = cow.fox1.de" → "cow.fox1.de"
        m = re.search(r'CN\s*=\s*(.+)', subj)
        if m:
            data["mailcow.acme.cert.subject"] = m.group(1).strip()

    # Issuer
    iss = run(f'openssl x509 -in "{cert_path}" -noout -issuer 2>/dev/null')
    if iss:
        m = re.search(r'CN\s*=\s*(.+)', iss)
        if m:
            data["mailcow.acme.cert.issuer"] = m.group(1).strip()

    # Dates
    dates = run(f'openssl x509 -in "{cert_path}" -noout -dates 2>/dev/null')
    if dates:
        for line in dates.splitlines():
            if line.startswith("notBefore="):
                data["mailcow.acme.cert.valid.from"] = line.split("=", 1)[1].strip()
            elif line.startswith("notAfter="):
                data["mailcow.acme.cert.valid.until"] = line.split("=", 1)[1].strip()

    # Days left
    enddate = run(f'openssl x509 -in "{cert_path}" -noout -enddate 2>/dev/null')
    if enddate:
        # "notAfter=May 16 21:39:00 2026 GMT"
        m = re.search(r'notAfter=(.+)', enddate)
        if m:
            try:
                end_str = m.group(1).strip()
                # Parse "Feb 15 21:39:00 2026 GMT"
                end_dt = datetime.strptime(end_str, "%b %d %H:%M:%S %Y %Z")
                end_dt = end_dt.replace(tzinfo=timezone.utc)
                days_left = (end_dt - datetime.now(timezone.utc)).days
                data["mailcow.acme.cert.days.left"] = max(0, days_left)
            except (ValueError, Exception):
                pass

    # Serial
    serial = run(f'openssl x509 -in "{cert_path}" -noout -serial 2>/dev/null')
    if serial:
        data["mailcow.acme.cert.serial"] = serial.split("=", 1)[-1].strip()

    return data


def collect_alias(mysql_container, dbpass):
    """Alias monitoring: count, active, forwarding."""
    data = {
        "mailcow.alias.total": 0,
        "mailcow.alias.active": 0,
        "mailcow.alias.inactive": 0,
        "mailcow.alias.forwarding": 0,
        "mailcow.alias.internal": 0,
    }
    if not mysql_container or not dbpass:
        return data

    raw = mysql_exec(mysql_container, dbpass,
        "SELECT address, goto, active, internal FROM alias", timeout=10)
    if not raw:
        return data

    aliases = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4:
            aliases.append({
                "address": parts[0],
                "goto": parts[1],
                "active": int(parts[2]),
                "internal": int(parts[3]),
            })

    data["mailcow.alias.total"] = len(aliases)
    data["mailcow.alias.active"] = sum(1 for a in aliases if a["active"] == 1)
    data["mailcow.alias.inactive"] = sum(1 for a in aliases if a["active"] == 0)
    data["mailcow.alias.internal"] = sum(1 for a in aliases if a["internal"] == 1)

    # Real forwarding aliases: address != goto (not just self-references)
    data["mailcow.alias.forwarding"] = sum(
        1 for a in aliases
        if a["active"] == 1 and a["address"] != a["goto"]
        and not a["goto"].endswith("@localhost"))

    return data


def collect_lld(mysql_container, dbpass):
    """Collect Low-Level Discovery data for Zabbix LLD."""
    data = {
        "mailcow.lld.domains": "[]",
        "mailcow.lld.domain.data": "{}",
        "mailcow.lld.mailboxes": "[]",
        "mailcow.lld.mailbox.data": "{}",
        "mailcow.lld.syncjobs": "[]",
        "mailcow.lld.syncjob.data": "{}",
    }
    if not mysql_container or not dbpass:
        return data

    # === Domain Discovery ===
    dom_sql = ("SELECT d.domain, d.aliases, d.mailboxes, d.maxquota, d.quota, d.active, "
               "COUNT(DISTINCT m.username) as mb_count, COALESCE(SUM(q.bytes),0) as used_bytes, "
               "(SELECT COUNT(*) FROM alias a WHERE a.domain=d.domain AND a.active=1) as alias_count, "
               "COALESCE((SELECT COUNT(*) FROM dkim dk WHERE dk.domain=d.domain LIMIT 1),0) as dkim_in_db "
               "FROM domain d "
               "LEFT JOIN mailbox m ON d.domain=m.domain AND (m.kind='' OR m.kind IS NULL) "
               "LEFT JOIN quota2 q ON m.username=q.username "
               "GROUP BY d.domain")
    dom_raw = mysql_exec(mysql_container, dbpass, dom_sql, timeout=15)
    if dom_raw:
        discovery = []
        domain_data = {}
        for line in dom_raw.splitlines():
            p = line.split("\t")
            if len(p) >= 8:
                dom = p[0]
                active = int(p[5])
                mb_count = int(p[6])
                used_bytes = int(p[7])
                max_aliases = int(p[1])
                max_mailboxes = int(p[2])
                maxquota_mb = int(p[3])
                quota_mb = int(p[4])
                alias_count = int(p[8]) if len(p) >= 9 else 0
                dkim_in_db = int(p[9]) if len(p) >= 10 else 0

                dkim_path = os.path.join(
                    MAILCOW_DIR, "data", "conf", "rspamd", "override.d", f"{dom}.dkim.key")
                dkim_exists = 1 if (os.path.exists(dkim_path) or dkim_in_db > 0) else 0

                discovery.append({
                    "{#DOMAIN}": dom,
                    "{#ACTIVE}": str(active),
                })
                domain_data[dom] = {
                    "active": active,
                    "mailbox_count": mb_count,
                    "alias_count": alias_count,
                    "max_aliases": max_aliases,
                    "max_mailboxes": max_mailboxes,
                    "maxquota_mb": maxquota_mb,
                    "quota_mb": quota_mb,
                    "used_mb": used_bytes // 1048576,
                    "usage_pct": round(used_bytes * 100 / (quota_mb * 1048576), 1) if quota_mb > 0 else 0,
                    "dkim_exists": dkim_exists,
                }
        data["mailcow.lld.domains"] = json.dumps(discovery)
        data["mailcow.lld.domain.data"] = json.dumps(domain_data)

    # === Mailbox Discovery ===
    mb_sql = ("SELECT m.username, m.domain, m.quota, m.active, COALESCE(q.bytes,0) "
              "FROM mailbox m LEFT JOIN quota2 q ON m.username=q.username "
              "WHERE m.kind='' OR m.kind IS NULL")
    mb_raw = mysql_exec(mysql_container, dbpass, mb_sql, timeout=15)
    if mb_raw:
        discovery = []
        mailbox_data = {}
        for line in mb_raw.splitlines():
            p = line.split("\t")
            if len(p) >= 5:
                user = p[0]
                domain = p[1]
                quota = int(p[2])
                active = int(p[3])
                used = int(p[4])
                quota_mb = quota // 1048576
                used_mb = used // 1048576
                pct = round(used * 100 / quota, 1) if quota > 0 else 0

                discovery.append({
                    "{#MAILBOX}": user,
                    "{#DOMAIN}": domain,
                    "{#ACTIVE}": str(active),
                })
                mailbox_data[user] = {
                    "domain": domain,
                    "active": active,
                    "quota_mb": quota_mb,
                    "used_mb": used_mb,
                    "usage_pct": pct,
                }
        data["mailcow.lld.mailboxes"] = json.dumps(discovery)
        data["mailcow.lld.mailbox.data"] = json.dumps(mailbox_data)

    # === Sync Job Discovery ===
    sync_sql = ("SELECT id, user2, host1, active, is_running, "
                "COALESCE(success,-1), COALESCE(exit_status,'unknown'), "
                "COALESCE(UNIX_TIMESTAMP(last_run),0) "
                "FROM imapsync")
    sync_raw = mysql_exec(mysql_container, dbpass, sync_sql, timeout=15)
    if sync_raw:
        discovery = []
        syncjob_data = {}
        for line in sync_raw.splitlines():
            p = line.split("\t")
            if len(p) >= 8:
                job_id = p[0]
                user = p[1]
                host = p[2]
                active = int(p[3])
                running = int(p[4])
                success = int(p[5])
                exit_status = p[6]
                last_run = int(p[7])

                discovery.append({
                    "{#SYNCJOB_ID}": job_id,
                    "{#SYNCJOB_USER}": user,
                    "{#SYNCJOB_HOST}": host,
                    "{#ACTIVE}": str(active),
                })
                syncjob_data[job_id] = {
                    "user": user,
                    "host": host,
                    "active": active,
                    "running": running,
                    "success": success,
                    "exit_status": exit_status,
                    "last_run": last_run,
                    "age_hours": (now() - last_run) // 3600 if last_run > 0 else -1,
                }
        data["mailcow.lld.syncjobs"] = json.dumps(discovery)
        data["mailcow.lld.syncjob.data"] = json.dumps(syncjob_data)

    return data


def collect_docker_health():
    """Collect Docker container health — optimized: targeted stats + batched inspect (#4)."""
    data = {
        "mailcow.docker.containers": "[]",
        "mailcow.docker.container.data": "{}",
        "mailcow.docker.total": 0,
        "mailcow.docker.running": 0,
        "mailcow.docker.restarts.total": 0,
        "mailcow.docker.mem.total.mb": 0,
        "mailcow.docker.cpu.total": 0,
    }

    # Step 0: All containers (incl. stopped) for correct total
    all_raw = run_cmd(
        ["docker", "ps", "--all", "--filter", "name=mailcow", "--format", "{{.Names}}"],
        timeout=10)
    total_count = len([n for n in all_raw.splitlines() if n.strip()]) if all_raw else 0

    # Step 1: Get only running Mailcow container names (fast, no stats)
    names_raw = run_cmd(
        ["docker", "ps", "--filter", "name=mailcow", "--format", "{{.Names}}"],
        timeout=10)
    if not names_raw:
        data["mailcow.docker.total"] = total_count
        return data

    container_names = [n.strip() for n in names_raw.splitlines() if n.strip()]
    if not container_names:
        data["mailcow.docker.total"] = total_count
        return data

    # Step 2: docker stats ONLY for known containers (faster than all + grep)
    names_args = " ".join(f'"{n}"' for n in container_names)
    stats_raw = run(
        f'docker stats --no-stream --format '
        f'"{{{{.Name}}}}|{{{{.CPUPerc}}}}|{{{{.MemUsage}}}}|{{{{.MemPerc}}}}|{{{{.PIDs}}}}" '
        f'{names_args} 2>/dev/null',
        timeout=30)

    # Step 3: ONE docker inspect for ALL containers (instead of N individual calls)
    inspect_fmt = '{{.Name}}|{{.RestartCount}}|{{.State.StartedAt}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}'
    inspect_raw = run_cmd(
        ["docker", "inspect", "--format", inspect_fmt] + container_names,
        timeout=15)

    # Parse inspect info
    restart_map = {}
    if inspect_raw:
        for line in inspect_raw.splitlines():
            parts = line.split("|")
            if len(parts) >= 4:
                name = parts[0].strip().lstrip("/")
                short = name.replace("mailcowdockerized-", "").replace("-mailcow-1", "").replace("-mailcow-", "-")
                try:
                    restarts = int(parts[1].strip())
                except ValueError:
                    restarts = 0
                started = parts[2].strip()
                health = parts[3].strip()
                uptime_h = -1
                try:
                    st = datetime.fromisoformat(started.replace("Z", "+00:00"))
                    uptime_h = int((datetime.now(timezone.utc) - st).total_seconds() // 3600)
                except (ValueError, Exception):
                    pass
                restart_map[name] = {
                    "short": short,
                    "restarts": restarts,
                    "uptime_h": uptime_h,
                    "health": health if health and health != "<no value>" else "none",
                }

    # Parse stats
    discovery = []
    container_data = {}
    total_mem_mb = 0
    total_cpu = 0.0
    total_restarts = 0

    if stats_raw:
        for line in stats_raw.splitlines():
            parts = line.split("|")
            if len(parts) < 5:
                continue

            name = parts[0].strip()
            cpu_str = parts[1].strip().replace("%", "")
            mem_usage_str = parts[2].strip()
            mem_pct_str = parts[3].strip().replace("%", "")
            pids_str = parts[4].strip()

            short = name.replace("mailcowdockerized-", "").replace("-mailcow-1", "").replace("-mailcow-", "-")

            try:
                cpu = float(cpu_str)
            except ValueError:
                cpu = 0.0

            try:
                mem_pct = float(mem_pct_str)
            except ValueError:
                mem_pct = 0.0

            # Parse mem usage "24.05MiB / 7.575GiB"
            mem_mb = 0
            try:
                used_part = mem_usage_str.split("/")[0].strip()
                if "GiB" in used_part:
                    mem_mb = int(float(used_part.replace("GiB", "").strip()) * 1024)
                elif "MiB" in used_part:
                    mem_mb = int(float(used_part.replace("MiB", "").strip()))
                elif "KiB" in used_part:
                    mem_mb = max(1, int(float(used_part.replace("KiB", "").strip()) / 1024))
            except (ValueError, IndexError):
                pass

            try:
                pids = int(pids_str)
            except ValueError:
                pids = 0

            rinfo = restart_map.get(name, {})
            restarts = rinfo.get("restarts", 0)
            uptime_h = rinfo.get("uptime_h", -1)
            health = rinfo.get("health", "none")

            total_mem_mb += mem_mb
            total_cpu += cpu
            total_restarts += restarts

            discovery.append({
                "{#CONTAINER}": short,
                "{#CONTAINER_FULL}": name,
            })
            container_data[short] = {
                "cpu": round(cpu, 2),
                "mem_mb": mem_mb,
                "mem_pct": round(mem_pct, 2),
                "pids": pids,
                "restarts": restarts,
                "uptime_h": uptime_h,
                "health": health,
            }

    data["mailcow.docker.containers"] = json.dumps(discovery)
    data["mailcow.docker.container.data"] = json.dumps(container_data)
    data["mailcow.docker.total"] = total_count
    data["mailcow.docker.running"] = len(discovery)
    data["mailcow.docker.restarts.total"] = total_restarts
    data["mailcow.docker.mem.total.mb"] = total_mem_mb
    data["mailcow.docker.cpu.total"] = round(total_cpu, 2)

    return data


def collect_memcached(container):
    """Collect Memcached stats (used by SOGo for session storage)."""
    data = {
        "mailcow.sogo.memcached.items": 0,
        "mailcow.sogo.memcached.bytes": 0,
        "mailcow.sogo.memcached.limit.mb": 0,
        "mailcow.sogo.memcached.hits": 0,
        "mailcow.sogo.memcached.misses": 0,
        "mailcow.sogo.memcached.hit.rate": 0,
        "mailcow.sogo.memcached.evictions": 0,
        "mailcow.sogo.memcached.uptime": 0,
    }

    if not container:
        return data

    stats_raw = run(
        f'docker exec {container} sh -c "echo stats | nc 127.0.0.1 11211" 2>/dev/null',
        timeout=10)

    if not stats_raw:
        return data

    stats = {}
    for line in stats_raw.splitlines():
        if line.startswith("STAT "):
            parts = line.split()
            if len(parts) >= 3:
                stats[parts[1]] = parts[2]

    curr_items = int(stats.get("curr_items", 0))
    bytes_used = int(stats.get("bytes", 0))
    limit_bytes = int(stats.get("limit_maxbytes", 0))
    hits = int(stats.get("get_hits", 0))
    misses = int(stats.get("get_misses", 0))
    evictions = int(stats.get("evictions", 0))
    uptime = int(stats.get("uptime", 0))

    total_gets = hits + misses
    hit_rate = round(hits * 100 / total_gets, 1) if total_gets > 0 else 0

    data["mailcow.sogo.memcached.items"] = curr_items
    data["mailcow.sogo.memcached.bytes"] = bytes_used
    data["mailcow.sogo.memcached.limit.mb"] = limit_bytes // (1024 * 1024)
    data["mailcow.sogo.memcached.hits"] = hits
    data["mailcow.sogo.memcached.misses"] = misses
    data["mailcow.sogo.memcached.hit.rate"] = hit_rate
    data["mailcow.sogo.memcached.evictions"] = evictions
    data["mailcow.sogo.memcached.uptime"] = uptime

    return data


def collect_redis(container):
    """Collect Redis metrics via redis-cli INFO all."""
    data = {
        "mailcow.redis.running": 0,
        "mailcow.redis.used_memory": 0,
        "mailcow.redis.used_memory_peak": 0,
        "mailcow.redis.keyspace_hits": 0,
        "mailcow.redis.keyspace_misses": 0,
        "mailcow.redis.connected_clients": 0,
        "mailcow.redis.evicted_keys": 0,
        "mailcow.redis.rdb_last_save_time": 0,
        "mailcow.redis.uptime_in_seconds": 0,
        "mailcow.redis.hit_ratio": 0.0,
    }

    if not container:
        return data

    raw = run_cmd(["docker", "exec", container, "redis-cli", "INFO", "all"], timeout=10)
    if not raw:
        return data

    data["mailcow.redis.running"] = 1

    fields = {}
    for line in raw.splitlines():
        if ":" in line and not line.startswith("#"):
            k, _, v = line.partition(":")
            fields[k.strip()] = v.strip()

    def _int(key):
        try:
            return int(fields.get(key, 0))
        except (ValueError, TypeError):
            return 0

    data["mailcow.redis.used_memory"] = _int("used_memory")
    data["mailcow.redis.used_memory_peak"] = _int("used_memory_peak")
    data["mailcow.redis.keyspace_hits"] = _int("keyspace_hits")
    data["mailcow.redis.keyspace_misses"] = _int("keyspace_misses")
    data["mailcow.redis.connected_clients"] = _int("connected_clients")
    data["mailcow.redis.evicted_keys"] = _int("evicted_keys")
    data["mailcow.redis.rdb_last_save_time"] = _int("rdb_last_save_time")
    data["mailcow.redis.uptime_in_seconds"] = _int("uptime_in_seconds")

    hits = data["mailcow.redis.keyspace_hits"]
    misses = data["mailcow.redis.keyspace_misses"]
    total = hits + misses
    data["mailcow.redis.hit_ratio"] = round(hits * 100 / total, 1) if total > 0 else 100.0

    return data


def collect_quarantine(mysql_container, dbpass):
    """Collect quarantine stats from MySQL."""
    data = {
        "mailcow.quarantine.total": 0,
        "mailcow.quarantine.spam": 0,
        "mailcow.quarantine.virus": 0,
        "mailcow.quarantine.age.oldest.hours": 0,
        "mailcow.quarantine.age.newest.hours": 0,
        "mailcow.quarantine.top.domains": "none",
    }

    if not mysql_container or not dbpass:
        return data

    # Total count + age + spam/virus split in one query (M3)
    result = mysql_exec(mysql_container, dbpass,
        "SELECT COUNT(*), "
        "COALESCE(TIMESTAMPDIFF(HOUR, MIN(created), NOW()), 0), "
        "COALESCE(TIMESTAMPDIFF(HOUR, MAX(created), NOW()), 0), "
        "COALESCE(SUM(CASE WHEN action='reject' THEN 1 ELSE 0 END), 0), "
        "COALESCE(SUM(CASE WHEN action='virus' THEN 1 ELSE 0 END), 0) "
        "FROM quarantine", timeout=10)

    if result:
        for line in result.splitlines():
            parts = line.split('\t')
            if len(parts) >= 5 and parts[0].isdigit():
                try:
                    data["mailcow.quarantine.total"] = int(parts[0])
                    data["mailcow.quarantine.age.oldest.hours"] = int(parts[1])
                    data["mailcow.quarantine.age.newest.hours"] = int(parts[2])
                    data["mailcow.quarantine.spam"] = int(parts[3])
                    data["mailcow.quarantine.virus"] = int(parts[4])
                except ValueError:
                    pass

    # Top Domains (separate query — GROUP BY doesn't mix with scalar aggregates)
    if data["mailcow.quarantine.total"] > 0:
        # Top Domains
        result = mysql_exec(mysql_container, dbpass,
            "SELECT SUBSTRING_INDEX(rcpt,'@',-1) as domain, COUNT(*) as cnt "
            "FROM quarantine GROUP BY domain ORDER BY cnt DESC LIMIT 5",
            timeout=10)

        if result:
            domains = []
            for line in result.splitlines():
                parts = line.split('\t')
                if len(parts) >= 2:
                    domains.append(f"{parts[0]}:{parts[1]}")
            if domains:
                data["mailcow.quarantine.top.domains"] = ",".join(domains)

    return data


def collect_queue_age(postfix_container):
    """Collect mail queue age — oldest and count of deferred mails."""
    data = {
        "mailcow.queue.deferred": 0,
        "mailcow.queue.active": 0,
        "mailcow.queue.age.oldest.hours": 0,
        "mailcow.queue.hold": 0,
    }

    if not postfix_container:
        return data

    # Deferred count
    result = docker_exec(postfix_container,
        'sh -c "find /var/spool/postfix/deferred -type f 2>/dev/null | wc -l"',
        timeout=10)
    if result:
        try:
            data["mailcow.queue.deferred"] = int(result.strip())
        except ValueError:
            pass

    # Active count
    result = docker_exec(postfix_container,
        'sh -c "find /var/spool/postfix/active -type f 2>/dev/null | wc -l"',
        timeout=10)
    if result:
        try:
            data["mailcow.queue.active"] = int(result.strip())
        except ValueError:
            pass

    # Hold count
    result = docker_exec(postfix_container,
        'sh -c "find /var/spool/postfix/hold -type f 2>/dev/null | wc -l"',
        timeout=10)
    if result:
        try:
            data["mailcow.queue.hold"] = int(result.strip())
        except ValueError:
            pass

    # Oldest deferred mail (hours)
    if data["mailcow.queue.deferred"] > 0:
        result = docker_exec(postfix_container,
            "sh -c \"find /var/spool/postfix/deferred -type f -printf '%T@\\n' 2>/dev/null | sort -n | head -1\"",
            timeout=10)
        if result and result.strip():
            try:
                oldest_ts = float(result.strip())
                age_hours = int((time.time() - oldest_ts) / 3600)
                data["mailcow.queue.age.oldest.hours"] = max(0, age_hours)
            except (ValueError, Exception):
                pass

    return data


def collect_version():
    """Collect version/update metrics. git fetch once per hour (VERSION_CACHE)."""
    # Check cache — git fetch is a network call, not needed on every run
    try:
        cache_age = now() - int(os.path.getmtime(VERSION_CACHE))
        if cache_age <= VERSION_MAX_AGE:
            with open(VERSION_CACHE) as f:
                return json.load(f)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        pass

    data = {
        "mailcow.version.current": "unknown",
        "mailcow.version.branch": "unknown",
        "mailcow.version.commit": "unknown",
        "mailcow.version.date": "unknown",
        "mailcow.version.latest": "unknown",
        "mailcow.updates.available": 0,
        "mailcow.updates.commits.behind": 0,
        "mailcow.update.script.exists": 0,
    }

    git = f"cd {MAILCOW_DIR} &&"

    data["mailcow.version.current"] = run(
        f"{git} git describe --tags 2>/dev/null || git log -1 --format='%H' 2>/dev/null | cut -c1-8",
        default="unknown")
    data["mailcow.version.branch"] = run(f"{git} git rev-parse --abbrev-ref HEAD 2>/dev/null", default="unknown")
    data["mailcow.version.commit"] = run(f"{git} git rev-parse --short HEAD 2>/dev/null", default="unknown")
    data["mailcow.version.date"] = run(f"{git} git log -1 --format=%cd --date=short 2>/dev/null", default="unknown")

    # Fetch + latest (single network call per hour, skippable via SKIP_GIT_FETCH=true)
    if _MONITOR_CONF.get("SKIP_GIT_FETCH", "false").lower() not in ("true", "1", "yes"):
        run(f"{git} git fetch --tags origin 2>/dev/null", timeout=15)
    data["mailcow.version.latest"] = run(
        f"{git} git describe --tags $(git rev-list --tags --max-count=1) 2>/dev/null",
        default="unknown")

    # Update check
    head = run(f"{git} git rev-parse HEAD 2>/dev/null")
    upstream = run(f"{git} git rev-parse @{{u}} 2>/dev/null")
    if head and upstream and head != upstream:
        data["mailcow.updates.available"] = 1

    data["mailcow.updates.commits.behind"] = run_int(
        f"{git} git rev-list --count HEAD..@{{u}} 2>/dev/null")

    if os.path.isfile(os.path.join(MAILCOW_DIR, "update.sh")):
        data["mailcow.update.script.exists"] = 1

    # Write cache
    try:
        with open(VERSION_CACHE + ".tmp", "w") as f:
            json.dump(data, f)
        os.rename(VERSION_CACHE + ".tmp", VERSION_CACHE)
    except OSError:
        pass

    return data


def collect_meta():
    """Collect agent/meta metrics."""
    data = {
        "zabbix.agent.running": 0,
        "zabbix.agent.uptime": 0,
        "zabbix.agent.restarts": 0,
        "zabbix.agent.configs": 0,
        "zabbix.agent.log.errors": 0,
        "zabbix.agent.log.warnings": 0,
        "zabbix.agent.timeout": 3,
        "zabbix.agent.unsafe": 0,
    }

    # Agent running
    data["zabbix.agent.running"] = 1 if run("systemctl is-active zabbix-agent2 2>/dev/null") == "active" else 0

    # Uptime
    ts = run("systemctl show zabbix-agent2 --property=ActiveEnterTimestamp --value 2>/dev/null")
    if ts and ts != "0":
        start = run_int(f'date -d "{ts}" +%s 2>/dev/null')
        if start > 0:
            data["zabbix.agent.uptime"] = now() - start

    # Restarts
    data["zabbix.agent.restarts"] = run_int(
        "systemctl show zabbix-agent2 --property=NRestarts --value 2>/dev/null")

    # Config count
    configs = list(Path("/etc/zabbix/zabbix_agent2.d/").glob("mailcow*.conf"))
    data["zabbix.agent.configs"] = len(configs)

    # Log analysis
    log_content = run("tail -100 /var/log/zabbix/zabbix_agent2.log 2>/dev/null")
    if log_content:
        data["zabbix.agent.log.errors"] = sum(
            1 for l in log_content.splitlines() if "error" in l.lower())
        data["zabbix.agent.log.warnings"] = sum(
            1 for l in log_content.splitlines() if "warning" in l.lower())

    # Config values
    agent_conf = ""
    try:
        with open("/etc/zabbix/zabbix_agent2.conf") as f:
            agent_conf = f.read()
    except FileNotFoundError:
        pass

    for line in agent_conf.splitlines():
        if line.startswith("Timeout="):
            data["zabbix.agent.timeout"] = int(line.split("=")[1].strip())
        elif line.startswith("UnsafeUserParameters="):
            data["zabbix.agent.unsafe"] = int(line.split("=")[1].strip())

    return data


def collect_backup(backup_path):
    """Collect backup metrics."""
    data = {
        "mailcow.backup.age": 999999,
        "mailcow.backup.size": 0,
        "mailcow.backup.zero.files": 0,
        "mailcow.backup.last.timestamp": 0,
        "mailcow.backup.dir.exists": 0,
        "mailcow.backup.count": 0,
        "mailcow.backup.disk.free": 0,
        "mailcow.backup.script.exists": 0,
    }

    if os.path.isfile(os.path.join(MAILCOW_DIR, "helper-scripts/backup_and_restore.sh")):
        data["mailcow.backup.script.exists"] = 1

    if not os.path.isdir(backup_path):
        return data

    data["mailcow.backup.dir.exists"] = 1

    # Disk free
    df_out = run(f"df '{backup_path}' 2>/dev/null")
    for line in df_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            data["mailcow.backup.disk.free"] = 100 - int(parts[4].replace("%", ""))
            break

    # Find backup directories
    backup_dirs = []
    try:
        for entry in os.scandir(backup_path):
            if entry.is_dir(follow_symlinks=True) and entry.name.startswith("mailcow-"):
                backup_dirs.append(entry)
    except OSError:
        pass

    data["mailcow.backup.count"] = len(backup_dirs)

    if not backup_dirs:
        return data

    # Most recent backup
    newest = max(backup_dirs, key=lambda e: e.stat(follow_symlinks=True).st_mtime)
    newest_mtime = int(newest.stat(follow_symlinks=True).st_mtime)
    data["mailcow.backup.last.timestamp"] = newest_mtime
    data["mailcow.backup.age"] = (now() - newest_mtime) // 3600

    # Size of most recent backup
    data["mailcow.backup.size"] = run_int(f"du -sm '{newest.path}' 2>/dev/null | cut -f1")

    # Zero-size files
    data["mailcow.backup.zero.files"] = run_int(
        f"find '{newest.path}' -type f -size 0 ! -path '*/.*' 2>/dev/null | wc -l")

    return data


def collect_slow():
    """Slow checks: TLS, DNS, RBL, Open Relay. Cache: 1h. Parallelized (#6)."""
    # Check cache
    try:
        cache_age = now() - int(os.path.getmtime(SLOW_CACHE))
        if cache_age <= SLOW_MAX_AGE:
            with open(SLOW_CACHE) as f:
                return json.load(f)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        pass

    # All checks as (key, command, is_int) triples
    checks = [
        # TLS
        ("mailcow.tls.cert.days.443", "/usr/local/bin/check_tls.sh cert_days 443 2>/dev/null", True),
        ("mailcow.tls.cert.days.587", "/usr/local/bin/check_tls.sh cert_days 587 2>/dev/null", True),
        ("mailcow.tls.cert.days.993", "/usr/local/bin/check_tls.sh cert_days 993 2>/dev/null", True),
        ("mailcow.tls.cert.raw.443", "/usr/local/bin/check_tls.sh cert_raw 443 2>/dev/null", False),
        ("mailcow.tls.cert.raw.587", "/usr/local/bin/check_tls.sh cert_raw 587 2>/dev/null", False),
        ("mailcow.tls.cert.raw.993", "/usr/local/bin/check_tls.sh cert_raw 993 2>/dev/null", False),
        ("mailcow.tls.https.check", "/usr/local/bin/check_tls.sh port_check 443 2>/dev/null", True),
        ("mailcow.tls.submission.check", "/usr/local/bin/check_tls.sh port_check 587 2>/dev/null", True),
        ("mailcow.tls.imaps.check", "/usr/local/bin/check_tls.sh port_check 993 2>/dev/null", True),
        ("mailcow.ui.check", "/usr/local/bin/check_tls.sh ui_check 2>/dev/null", True),
        ("mailcow.smtp.banner.25",  "/usr/local/bin/check_tls.sh smtp_banner 25 2>/dev/null",  True),
        ("mailcow.smtp.banner.587", "/usr/local/bin/check_tls.sh smtp_banner 587 2>/dev/null", True),
        # DNS
        ("mailcow.dns.spf.exists", "/usr/local/bin/check_dns.sh spf 2>/dev/null", True),
        ("mailcow.dns.dkim.exists", "/usr/local/bin/check_dns.sh dkim 2>/dev/null", True),
        ("mailcow.dns.dmarc.exists", "/usr/local/bin/check_dns.sh dmarc 2>/dev/null", True),
        ("mailcow.dns.ptr.valid", "/usr/local/bin/check_ptr.sh 2>/dev/null", True),
        ("mailcow.dns.detail", "/usr/local/bin/check_dns.sh detail 2>/dev/null", False),
        ("mailcow.dns.domains", "/usr/local/bin/check_dns.sh domains 2>/dev/null", False),
        # RBL
        ("mailcow.security.rbl.listed", "/usr/local/bin/check_rbl.sh 2>/dev/null", True),
        ("mailcow.security.rbl.detail", "/usr/local/bin/check_rbl.sh detail 2>/dev/null", False),
        # Open Relay
        ("mailcow.security.open.relay", "/usr/local/bin/check_open_relay.sh 2>/dev/null", True),
        # Security Audit (#9): DANE, MTA-STS, TLS-RPT, BIMI
        ("mailcow.security.dane.exists", "/usr/local/bin/check_security_audit.sh dane 2>/dev/null", True),
        ("mailcow.security.mta_sts.exists", "/usr/local/bin/check_security_audit.sh mta_sts 2>/dev/null", True),
        ("mailcow.security.tls_rpt.exists", "/usr/local/bin/check_security_audit.sh tls_rpt 2>/dev/null", True),
        ("mailcow.security.bimi.exists", "/usr/local/bin/check_security_audit.sh bimi 2>/dev/null", True),
        ("mailcow.security.audit.score", "/usr/local/bin/check_security_audit.sh score 2>/dev/null", True),
        ("mailcow.security.audit.detail", "/usr/local/bin/check_security_audit.sh detail 2>/dev/null", False),
    ]

    data = {}

    def _run_check(item):
        key, cmd, is_int = item
        return key, run_int(cmd) if is_int else run(cmd)

    # Run in parallel (max 6 threads — I/O-bound)
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(_run_check, c): c[0] for c in checks}
        for f in as_completed(futures):
            try:
                key, val = f.result(timeout=60)
                data[key] = val
            except Exception:
                pass

    # Write cache
    try:
        with open(SLOW_CACHE + ".tmp", "w") as f:
            json.dump(data, f, indent=2)
        os.rename(SLOW_CACHE + ".tmp", SLOW_CACHE)
    except OSError:
        pass

    return data


def collect_mailflow(postfix_container):
    """Collect mailflow metrics via pflogsumm. Separate 5-min cache (#1)."""
    defaults = {
        # Grand Totals
        "mailcow.mail.received": 0,
        "mailcow.mail.delivered": 0,
        "mailcow.mail.forwarded": 0,
        "mailcow.mail.deferred": 0,
        "mailcow.mail.bounced": 0,
        "mailcow.mail.rejected": 0,
        "mailcow.mail.reject.rate": 0,
        "mailcow.mail.bytes.received": 0,
        "mailcow.mail.bytes.delivered": 0,
        "mailcow.mail.senders": 0,
        "mailcow.mail.recipients": 0,
        "mailcow.mail.sending.domains": 0,
        "mailcow.mail.recipient.domains": 0,
        # Top lists
        "mailcow.mail.top.senders": "-",
        "mailcow.mail.top.recipients": "-",
        "mailcow.mail.top.sending.domains": "-",
        "mailcow.mail.top.recipient.domains": "-",
        # Reject-Details
        "mailcow.mail.reject.rbl": 0,
        "mailcow.mail.reject.unknown.user": 0,
        "mailcow.mail.reject.relay.denied": 0,
        "mailcow.mail.reject.domain.notfound": 0,
        "mailcow.mail.reject.cleanup": 0,
        "mailcow.mail.reject.detail": "-",
        # Bounce details
        "mailcow.mail.bounce.detail": "-",
        # Warnings
        "mailcow.mail.warnings.sasl": 0,
        "mailcow.mail.warnings.tls": 0,
        "mailcow.mail.warnings.dns": 0,
        "mailcow.mail.warnings.postscreen": 0,
    }

    # Check 5-min cache
    try:
        cache_age = now() - int(os.path.getmtime(MAILFLOW_CACHE))
        if cache_age <= MAILFLOW_MAX_AGE:
            with open(MAILFLOW_CACHE) as f:
                return json.load(f)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        pass

    if not postfix_container:
        return defaults

    # Check for pflogsumm
    has_pflogsumm = run_cmd(["which", "pflogsumm"])
    if not has_pflogsumm:
        return defaults

    # Run last hour of logs through pflogsumm
    raw = run(
        f'docker logs --since 1h "{postfix_container}" 2>&1 | pflogsumm 2>/dev/null',
        timeout=60)
    if not raw:
        return defaults

    data = dict(defaults)
    lines = raw.splitlines()

    # === Grand Totals parsen ===
    # Format: "   138   received" (nur Zahl + Keyword, NICHT "bytes received")
    grand_total_map = {
        "received": "mailcow.mail.received",
        "delivered": "mailcow.mail.delivered",
        "forwarded": "mailcow.mail.forwarded",
        "deferred": "mailcow.mail.deferred",
        "bounced": "mailcow.mail.bounced",
        "senders": "mailcow.mail.senders",
        "recipients": "mailcow.mail.recipients",
        "sending hosts/domains": "mailcow.mail.sending.domains",
        "recipient hosts/domains": "mailcow.mail.recipient.domains",
    }
    for line in lines:
        line_stripped = line.strip()

        # Exact match: "138   received" — NOT "4977k  bytes received"
        for keyword, key in grand_total_map.items():
            m = re.match(r'^(\d+)\s+' + re.escape(keyword) + r'$', line_stripped)
            if m:
                data[key] = int(m.group(1))

        # Rejected mit Prozentzahl
        if "rejected" in line_stripped and "%" in line_stripped:
            match = re.match(r'\s*(\d+)\s+rejected\s+\((\d+)%\)', line_stripped)
            if match:
                data["mailcow.mail.rejected"] = int(match.group(1))
                data["mailcow.mail.reject.rate"] = int(match.group(2))

        # Bytes: "   4977k  bytes received"
        if "bytes received" in line_stripped:
            data["mailcow.mail.bytes.received"] = _parse_bytes(line_stripped)
        elif "bytes delivered" in line_stripped:
            data["mailcow.mail.bytes.delivered"] = _parse_bytes(line_stripped)

    # === Parse sections ===
    sections = _split_sections(lines)

    # Top senders (by count)
    if "Senders by message count" in sections:
        top = _parse_top_list(sections["Senders by message count"], 5)
        data["mailcow.mail.top.senders"] = top if top else "-"

    # Top recipients (by count)
    if "Recipients by message count" in sections:
        top = _parse_top_list(sections["Recipients by message count"], 5)
        data["mailcow.mail.top.recipients"] = top if top else "-"

    # Top sending domains
    if "Host/Domain Summary: Messages Received" in sections:
        top = _parse_domain_list(sections["Host/Domain Summary: Messages Received"], 5)
        data["mailcow.mail.top.sending.domains"] = top if top else "-"

    # Top recipient domains
    if "Host/Domain Summary: Message Delivery" in sections:
        top = _parse_domain_list(sections["Host/Domain Summary: Message Delivery"], 5)
        data["mailcow.mail.top.recipient.domains"] = top if top else "-"

    # === Reject details ===
    if "message reject detail" in sections:
        reject_lines = sections["message reject detail"]
        reject_text = "\n".join(reject_lines)

        # RBL rejects (spamhaus, barracuda, etc.)
        rbl_count = 0
        for rl in reject_lines:
            if "blocked using" in rl:
                m = re.match(r'\s+blocked using .+ \(total: (\d+)\)', rl)
                if m:
                    rbl_count += int(m.group(1))
        data["mailcow.mail.reject.rbl"] = rbl_count

        # Unknown user
        m = re.search(r'User unknown in virtual mailbox table \(total: (\d+)\)', reject_text)
        if m:
            data["mailcow.mail.reject.unknown.user"] = int(m.group(1))

        # Relay access denied
        m = re.search(r'Relay access denied \(total: (\d+)\)', reject_text)
        if m:
            data["mailcow.mail.reject.relay.denied"] = int(m.group(1))

        # Domain not found
        m = re.search(r'Domain not found \(total: (\d+)\)', reject_text)
        if m:
            data["mailcow.mail.reject.domain.notfound"] = int(m.group(1))

        # Cleanup (rspamd/milter rejects)
        m = re.search(r'END-OF-MESSAGE \(total: (\d+)\)', reject_text)
        if m:
            data["mailcow.mail.reject.cleanup"] = int(m.group(1))

        # Compact summary of reject reasons
        reject_parts = []
        if data["mailcow.mail.reject.rbl"] > 0:
            reject_parts.append(f'RBL:{data["mailcow.mail.reject.rbl"]}')
        if data["mailcow.mail.reject.unknown.user"] > 0:
            reject_parts.append(f'UnknownUser:{data["mailcow.mail.reject.unknown.user"]}')
        if data["mailcow.mail.reject.domain.notfound"] > 0:
            reject_parts.append(f'DomainNotFound:{data["mailcow.mail.reject.domain.notfound"]}')
        if data["mailcow.mail.reject.relay.denied"] > 0:
            reject_parts.append(f'RelayDenied:{data["mailcow.mail.reject.relay.denied"]}')
        if data["mailcow.mail.reject.cleanup"] > 0:
            reject_parts.append(f'Milter:{data["mailcow.mail.reject.cleanup"]}')
        data["mailcow.mail.reject.detail"] = ",".join(reject_parts) if reject_parts else "-"

    # === Bounce-Details ===
    if "message bounce detail (by relay)" in sections:
        bounce_lines = sections["message bounce detail (by relay)"]
        bounce_parts = []
        for bl in bounce_lines:
            m = re.match(r'\s+(\d+)\s+(.+)', bl.strip())
            if m and int(m.group(1)) > 0:
                bounce_parts.append(f'{m.group(2).strip()[:60]}:{m.group(1)}')
        data["mailcow.mail.bounce.detail"] = ",".join(bounce_parts[:5]) if bounce_parts else "-"

    # === Count warnings ===
    if "Warnings" in sections:
        warn_lines = sections["Warnings"]
        warn_text = "\n".join(warn_lines)
        data["mailcow.mail.warnings.sasl"] = _count_total(warn_text, "SASL")
        data["mailcow.mail.warnings.tls"] = _count_total(warn_text, "TLS")
        data["mailcow.mail.warnings.dns"] = _count_total(warn_text, "dnsblog")
        data["mailcow.mail.warnings.postscreen"] = _count_total(warn_text, "postscreen")

    # Write 5-min cache
    try:
        with open(MAILFLOW_CACHE + ".tmp", "w") as f:
            json.dump(data, f, indent=2)
        os.rename(MAILFLOW_CACHE + ".tmp", MAILFLOW_CACHE)
    except OSError:
        pass

    return data


def _parse_bytes(line):
    """Parse pflogsumm byte Angaben: '4977k', '12m', '2g'."""
    m = re.match(r'\s*([\d.]+)([kmgKMG]?)\s+bytes', line.strip())
    if not m:
        return 0
    val = float(m.group(1))
    unit = m.group(2).lower()
    if unit == 'k':
        return int(val * 1024)
    elif unit == 'm':
        return int(val * 1024 * 1024)
    elif unit == 'g':
        return int(val * 1024 * 1024 * 1024)
    return int(val)


def _split_sections(lines):
    """Split pflogsumm output into sections (header → lines)."""
    sections = {}
    current = None
    for line in lines:
        # Section detected when next line contains only ---
        if line.strip() and all(c == '-' for c in line.strip()):
            continue
        # New section: line without leading whitespace, followed by ---
        if line and not line.startswith(" ") and not line.startswith("\t") and line.strip():
            current = line.strip()
            if current not in sections:
                sections[current] = []
        elif current and line.strip():
            sections[current].append(line)
    return sections


def _parse_top_list(lines, count=5):
    """Parse 'count  address' Listen aus pflogsumm."""
    entries = []
    for line in lines:
        # "     72   smmsp@cow.fox1.de"
        m = re.match(r'\s*(\d+)\s+(\S+)', line)
        if m:
            entries.append(f'{m.group(2)}:{m.group(1)}')
    return ",".join(entries[:count]) if entries else ""


def _parse_domain_list(lines, count=5):
    """Parse Domain-Listen (sent cnt / msg cnt Format)."""
    entries = []
    for line in lines:
        # " 19     1452k       0     1.6 s    3.6 s  linuser.de"
        # oder " 74   161382   cow.fox1.de"
        parts = line.split()
        if len(parts) >= 2:
            # Domain ist letztes Feld
            domain = parts[-1]
            cnt = parts[0]
            if cnt.isdigit() and "." in domain:
                entries.append(f'{domain}:{cnt}')
    return ",".join(entries[:count]) if entries else ""


def _count_total(text, keyword):
    """Count occurrences of a keyword in warning sections."""
    count = 0
    for line in text.splitlines():
        if keyword.lower() in line.lower():
            m = re.match(r'\s*(\d+)\s+', line)
            if m:
                count += int(m.group(1))
    return count


def collect_system():
    """Collect host system metrics: NTP sync status and offset."""
    data = {
        "mailcow.system.ntp.synchronized": 0,
        "mailcow.system.ntp.offset.ms": 0.0,
        "mailcow.system.ntp.service": "unknown",
    }

    # Try timedatectl first (works on systemd hosts)
    td_out = run("timedatectl show 2>/dev/null")
    if td_out:
        td = {}
        for line in td_out.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                td[k.strip()] = v.strip()
        synced = td.get("NTPSynchronized", "no")
        data["mailcow.system.ntp.synchronized"] = 1 if synced == "yes" else 0
        data["mailcow.system.ntp.service"] = td.get("NTPService", "systemd-timesyncd")

    # Try chronyc for offset (preferred NTP daemon on many servers)
    chrony_out = run("chronyc tracking 2>/dev/null")
    if chrony_out:
        for line in chrony_out.splitlines():
            if "System time" in line:
                # "System time     :  0.000012345 seconds fast of NTP time"
                m = re.search(r'([\d.]+)\s+seconds', line)
                if m:
                    try:
                        data["mailcow.system.ntp.offset.ms"] = round(float(m.group(1)) * 1000, 3)
                    except ValueError:
                        pass
                break
        data["mailcow.system.ntp.service"] = "chrony"
    elif not chrony_out:
        # Try ntpq as fallback
        ntpq_out = run("ntpq -c rv 2>/dev/null")
        for part in ntpq_out.split(","):
            part = part.strip()
            if part.startswith("offset="):
                try:
                    data["mailcow.system.ntp.offset.ms"] = round(float(part.split("=")[1]), 3)
                    data["mailcow.system.ntp.service"] = "ntpd"
                except (ValueError, IndexError):
                    pass
                break

    return data


def collect_nginx(container, hostname):
    """Collect Nginx metrics via stub_status and access.log analysis."""
    data = {
        "mailcow.nginx.running": 0,
        "mailcow.nginx.connections.active": 0,
        "mailcow.nginx.connections.reading": 0,
        "mailcow.nginx.connections.writing": 0,
        "mailcow.nginx.connections.waiting": 0,
        "mailcow.nginx.requests.total": 0,
        "mailcow.nginx.errors.4xx": 0,
        "mailcow.nginx.errors.5xx": 0,
    }
    if not container:
        return data

    pid = docker_exec(container, "pgrep -x nginx 2>/dev/null | head -1")
    if not pid:
        return data
    data["mailcow.nginx.running"] = 1

    status_out = docker_exec(container,
        "curl -sf http://127.0.0.1/nginx_status 2>/dev/null", timeout=5)
    if status_out:
        m = re.search(r'Active connections:\s+(\d+)', status_out)
        if m:
            data["mailcow.nginx.connections.active"] = int(m.group(1))
        m = re.search(r'Reading:\s+(\d+)\s+Writing:\s+(\d+)\s+Waiting:\s+(\d+)', status_out)
        if m:
            data["mailcow.nginx.connections.reading"] = int(m.group(1))
            data["mailcow.nginx.connections.writing"] = int(m.group(2))
            data["mailcow.nginx.connections.waiting"] = int(m.group(3))
        lines = status_out.splitlines()
        if len(lines) >= 3:
            parts = lines[2].split()
            if len(parts) >= 3:
                try:
                    data["mailcow.nginx.requests.total"] = int(parts[2])
                except ValueError:
                    pass

    log_out = run_cmd(["docker", "logs", "--since", "5m", container], timeout=10)
    if not log_out:
        log_out = docker_exec(container,
            "tail -n 1000 /var/log/nginx/access.log 2>/dev/null", timeout=10)
    if log_out:
        cnt_4xx = 0
        cnt_5xx = 0
        for line in log_out.splitlines():
            m = re.search(r'" (\d{3}) ', line)
            if m:
                code = int(m.group(1))
                if 400 <= code < 500:
                    cnt_4xx += 1
                elif 500 <= code < 600:
                    cnt_5xx += 1
        data["mailcow.nginx.errors.4xx"] = cnt_4xx
        data["mailcow.nginx.errors.5xx"] = cnt_5xx

    return data


def collect_sogo(container, hostname):
    """Collect SOGo health metrics: process count and HTTP response time."""
    data = {
        "mailcow.sogo.running": 0,
        "mailcow.sogo.workers": 0,
        "mailcow.sogo.response.ms": 0,
    }
    if not container:
        return data

    workers_out = docker_exec(container, "pgrep -c sogod 2>/dev/null")
    try:
        workers = int(workers_out)
    except (ValueError, TypeError):
        return data

    if workers > 0:
        data["mailcow.sogo.running"] = 1
        data["mailcow.sogo.workers"] = workers

    if hostname and data["mailcow.sogo.running"]:
        resp = run(
            f'curl -o /dev/null -w "%{{time_total}}" -s --max-time 15 -k '
            f'"https://{hostname}/SOGo/" 2>/dev/null',
            timeout=20)
        try:
            data["mailcow.sogo.response.ms"] = round(float(resp) * 1000, 1)
        except (ValueError, TypeError):
            pass

    return data


def collect_unbound(container):
    """Collect Unbound DNS resolver metrics via unbound-control stats_noreset."""
    data = {
        "mailcow.unbound.running": 0,
        "mailcow.unbound.queries.total": 0,
        "mailcow.unbound.cache.hits": 0,
        "mailcow.unbound.cache.misses": 0,
        "mailcow.unbound.cache.hit_rate": 0.0,
        "mailcow.unbound.nxdomain": 0,
        "mailcow.unbound.uptime": 0,
        "mailcow.unbound.memory.mb": 0.0,
    }
    if not container:
        return data

    stats_out = docker_exec(container,
        "unbound-control stats_noreset 2>/dev/null", timeout=10)
    if not stats_out:
        return data

    data["mailcow.unbound.running"] = 1
    stats = {}
    for line in stats_out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            stats[k.strip()] = v.strip()

    def _si(key, default=0):
        try:
            return int(float(stats.get(key, default)))
        except (ValueError, TypeError):
            return default

    def _sf(key, default=0.0):
        try:
            return float(stats.get(key, default))
        except (ValueError, TypeError):
            return default

    queries = _si("total.num.queries")
    hits = _si("total.num.cachehits")
    misses = _si("total.num.cachemiss")
    nxdomain = _si("total.num.answer_nxdomain") + _si("total.num.dnserr")
    uptime = _sf("time.up")
    mem_sbrk = _sf("mem.total.sbrk")

    data["mailcow.unbound.queries.total"] = queries
    data["mailcow.unbound.cache.hits"] = hits
    data["mailcow.unbound.cache.misses"] = misses
    data["mailcow.unbound.cache.hit_rate"] = (
        round(hits / (hits + misses) * 100, 1) if (hits + misses) > 0 else 0.0)
    data["mailcow.unbound.nxdomain"] = nxdomain
    data["mailcow.unbound.uptime"] = int(uptime)
    data["mailcow.unbound.memory.mb"] = round(mem_sbrk / 1048576, 2) if mem_sbrk > 0 else 0.0

    return data


def collect_ratelimit(mysql_container, dbpass, watchdog_container):
    """Collect outbound ratelimit and spam detection metrics."""
    data = {
        "mailcow.ratelimit.hits": 0,
        "mailcow.ratelimit.exceeded": 0,
        "mailcow.outbound.spam.detected": 0,
    }

    if mysql_container and dbpass:
        tbl_check = mysql_exec(mysql_container, dbpass,
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema='mailcow' AND table_name='ratelimit'",
            timeout=5)
        if tbl_check and tbl_check.strip() == "1":
            hits_raw = mysql_exec(mysql_container, dbpass,
                "SELECT COUNT(*) FROM ratelimit "
                "WHERE created > NOW() - INTERVAL 1 HOUR",
                timeout=5)
            exceeded_raw = mysql_exec(mysql_container, dbpass,
                "SELECT COUNT(*) FROM ratelimit "
                "WHERE exceeded=1 AND created > NOW() - INTERVAL 1 HOUR",
                timeout=5)
            try:
                data["mailcow.ratelimit.hits"] = int(hits_raw.strip())
            except (ValueError, TypeError, AttributeError):
                pass
            try:
                data["mailcow.ratelimit.exceeded"] = int(exceeded_raw.strip())
            except (ValueError, TypeError, AttributeError):
                pass

    if watchdog_container:
        spam_out = docker_exec(watchdog_container,
            "sh -c \"grep -c 'outbound spam' /var/log/mailcow/watchdog.log 2>/dev/null || echo 0\"",
            timeout=10)
        try:
            data["mailcow.outbound.spam.detected"] = int(spam_out.strip())
        except (ValueError, TypeError):
            pass

    return data


# ====================================================================
# MAIN PROGRAM
# ====================================================================

def main():
    start_time = time.time()
    errors = []  # #10: error tracking per module

    # Read config
    config = read_config()

    # Discover containers once, centrally (#2)
    ct = find_all_containers()

    # Determine backup path (from config or auto-detect)
    backup_path = _MONITOR_CONF.get("BACKUP_PATH", "")
    if not backup_path or not os.path.isdir(backup_path):
        backup_path = "/opt/backup"
    if not os.path.isdir(backup_path):
        backup_path = "/backup"

    # Collect all metrics — with error tracking (#10)
    metrics = {"timestamp": now()}
    module_times = {}

    modules = [
        ("postfix",      lambda: collect_postfix(ct["postfix"])),
        ("postfix_logs", lambda: collect_postfix_logs()),
        ("dovecot",      lambda: collect_dovecot(ct["dovecot"])),
        ("rspamd",       lambda: collect_rspamd(ct["rspamd"])),
        ("fail2ban",     lambda: collect_fail2ban(ct["netfilter"])),
        ("disk",         lambda: collect_disk(ct["dovecot"])),
        ("sync",         lambda: collect_sync(ct["mysql"], config["dbpass"])),
        ("mailbox",      lambda: collect_mailbox(ct["mysql"], config["dbpass"])),
        ("alias",        lambda: collect_alias(ct["mysql"], config["dbpass"])),
        ("lld",          lambda: collect_lld(ct["mysql"], config["dbpass"])),
        ("docker",       lambda: collect_docker_health()),
        ("memcached",    lambda: collect_memcached(ct["memcached"])),
        ("redis",        lambda: collect_redis(ct["redis"])),
        ("quarantine",   lambda: collect_quarantine(ct["mysql"], config["dbpass"])),
        ("queue_age",    lambda: collect_queue_age(ct["postfix"])),
        ("clamav",       lambda: collect_clamav(ct["clamd"])),
        ("watchdog",     lambda: collect_watchdog(ct["watchdog"])),
        ("acme",         lambda: collect_acme()),
        ("version",      lambda: collect_version()),
        ("meta",         lambda: collect_meta()),
        ("backup",       lambda: collect_backup(backup_path)),
        ("mailflow",     lambda: collect_mailflow(ct["postfix"])),  # #1: separate 5-min cache
        ("slow",         lambda: collect_slow()),                    # #6: parallelized
        ("mysql",        lambda: collect_mysql_health(ct["mysql"], config["dbroot"], config["dbpass"])),
        ("system",       lambda: collect_system()),
        ("nginx",        lambda: collect_nginx(ct.get("nginx", ""), config["hostname"])),
        ("sogo",         lambda: collect_sogo(ct.get("sogo", ""), config["hostname"])),
        ("unbound",      lambda: collect_unbound(ct.get("unbound", ""))),
        ("ratelimit",    lambda: collect_ratelimit(ct["mysql"], config["dbpass"], ct["watchdog"])),
    ]

    for name, func in modules:
        t0 = time.time()
        try:
            metrics.update(func())
        except Exception as e:
            errors.append(f"{name}:{type(e).__name__}")
        module_times[name] = round(time.time() - t0, 2)

    # Config values
    metrics["mailcow.config.hostname"] = config["hostname"]
    metrics["mailcow.config.timezone"] = config["timezone"]

    # Collector self-monitoring (#10)
    duration = round(time.time() - start_time, 2)
    metrics["mailcow.collector.running"] = 1
    metrics["mailcow.collector.last_run"] = now()
    metrics["mailcow.collector.age"] = 0
    metrics["mailcow.collector.keys"] = len(metrics) + 5  # +5 for these keys themselves
    metrics["mailcow.collector.duration"] = duration
    metrics["mailcow.collector.errors"] = len(errors)
    metrics["mailcow.collector.error.detail"] = ",".join(errors) if errors else "-"
    metrics["mailcow.collector.module.times"] = json.dumps(module_times)

    # Write JSON atomically
    try:
        with open(OUTPUT_TMP, "w") as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False)
        os.rename(OUTPUT_TMP, OUTPUT)
        os.chmod(OUTPUT, 0o644)
    except OSError as e:
        print(f"ERROR: Failed to write JSON: {e}", file=sys.stderr)
        sys.exit(1)

    if errors:
        print(f"WARN: {len(metrics)} metrics in {duration}s, {len(errors)} errors: {','.join(errors)} -> {OUTPUT}")
    else:
        print(f"OK: {len(metrics)} metrics written in {duration}s -> {OUTPUT}")


if __name__ == "__main__":
    main()
