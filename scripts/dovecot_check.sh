#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - Dovecot Check
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Monitors Dovecot IMAP/POP3 (connections, login failures, quota)
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
DOVECOT_CONTAINER=$(docker ps --filter "name=dovecot" --format "{{.Names}}" 2>/dev/null | head -1)

if [ -z "$DOVECOT_CONTAINER" ]; then
    echo "0"
    exit 0
fi

CACHE_FILE="/var/tmp/dovecot_check.cache"
CACHE_MAX_AGE=60  # 60 seconds

# Update cache
update_cache() {
    # Filter log lines from the last 5 minutes by timestamp; fall back to tail on failure
    SINCE=$(date -d '5 minutes ago' '+%b %_d %H:%M' 2>/dev/null)
    if [ -n "$SINCE" ]; then
        LOGS=$(docker exec "$DOVECOT_CONTAINER" awk -v since="$SINCE" \
            'length($0) >= length(since) && substr($0,1,length(since)) >= since' \
            /var/log/dovecot.log 2>/dev/null)
    else
        LOGS=$(docker exec "$DOVECOT_CONTAINER" tail -1000 /var/log/dovecot.log 2>/dev/null)
    fi

    if [ -z "$LOGS" ]; then
        echo '{"imap_login_failed":0}' > "$CACHE_FILE"
        return
    fi

    # All counts in one pass
    IMAP_LOGIN_FAILED=$(echo "$LOGS" | grep -ci "imap.*authentication failed\|imap.*login failed" || echo 0)
    IMAP_DISCONNECTED=$(echo "$LOGS" | grep -ci "imap.*disconnected\|imap.*connection closed" || echo 0)
    POP3_LOGIN_FAILED=$(echo "$LOGS" | grep -ci "pop3.*authentication failed\|pop3.*login failed" || echo 0)
    IMAP_ERRORS=$(echo "$LOGS" | grep -ci "imap.*error" || echo 0)
    QUOTA_WARNINGS=$(echo "$LOGS" | grep -ci "quota.*warning\|quota.*exceeded" || echo 0)
    SYNC_ERRORS=$(echo "$LOGS" | grep -ci "sync.*error\|sync.*failed" || echo 0)

    # Write JSON
    cat > "$CACHE_FILE" << EOFJSON
{
  "imap_login_failed": $IMAP_LOGIN_FAILED,
  "imap_disconnected": $IMAP_DISCONNECTED,
  "pop3_login_failed": $POP3_LOGIN_FAILED,
  "imap_errors": $IMAP_ERRORS,
  "quota_warnings": $QUOTA_WARNINGS,
  "sync_errors": $SYNC_ERRORS
}
EOFJSON
}

case "$1" in
    process)
        docker ps --filter "name=dovecot" --filter "status=running" --format "{{.Names}}" 2>/dev/null | wc -l
        ;;
    connections)
        docker exec "$DOVECOT_CONTAINER" doveadm who 2>/dev/null | wc -l || echo 0
        ;;
    imap_login_failed|imap_disconnected|pop3_login_failed|imap_errors|quota_warnings|sync_errors)
        if [ ! -f "$CACHE_FILE" ] || [ $(($(date +%s) - $(stat -c %Y "$CACHE_FILE" 2>/dev/null || echo 0))) -gt $CACHE_MAX_AGE ]; then
            update_cache
        fi

        if command -v jq &>/dev/null; then
            cat "$CACHE_FILE" 2>/dev/null | jq -r ".$1 // 0" 2>/dev/null || echo 0
        else
            grep -oP "\"$1\":\s*\K\d+" "$CACHE_FILE" 2>/dev/null || echo 0
        fi
        ;;
    version)
        docker exec "$DOVECOT_CONTAINER" dovecot --version 2>/dev/null | awk '{print $1}' || echo "unknown"
        ;;
    *)
        echo 0
        ;;
esac
