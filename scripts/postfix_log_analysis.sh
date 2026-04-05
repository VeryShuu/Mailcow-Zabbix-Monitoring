#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - Postfix Log Analysis
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Analyses Postfix logs for SASL, Relay, TLS, Spam, Virus and Postscreen events
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
CONTAINER=$(docker ps --filter "name=postfix" --format "{{.Names}}" 2>/dev/null | grep -i mailcow | head -1)
if [ -z "$CONTAINER" ]; then
    echo 0
    exit 0
fi
CACHE_FILE="/var/tmp/postfix_log_analysis.cache"
CACHE_MAX_AGE=60  # 60 second cache

# Update cache if needed
update_cache() {
    # Filter log lines from the last 5 minutes by timestamp; fall back to tail on failure
    SINCE=$(date -d '5 minutes ago' '+%b %_d %H:%M' 2>/dev/null)
    if [ -n "$SINCE" ]; then
        LOGS=$(docker exec "$CONTAINER" awk -v since="$SINCE" \
            'length($0) >= length(since) && substr($0,1,length(since)) >= since' \
            /var/log/mail.log 2>/dev/null)
    else
        LOGS=$(docker exec "$CONTAINER" tail -1000 /var/log/mail.log 2>/dev/null)
    fi

    if [ -z "$LOGS" ]; then
        echo '{"sasl_auth_failed":0}' > "$CACHE_FILE"
        return
    fi

    # All counts in one awk pass (P4: single pass instead of 20 grep calls)
    eval "$(echo "$LOGS" | awk '
        /SASL.*authentication failed/           { sasl++ }
        /Relay access denied/                   { relay++ }
        /User unknown in/                       { user_unknown++ }
        /blocked using/                         { rbl++ }
        /Connection timed out/                  { conn_timeout++ }
        /TLS.*handshake failed|SSL.*error/      { tls++ }
        /mailbox.*full|quota.*exceeded|Disk quota/ { quota++ }
        /milter-reject.*Spam message rejected/  { spam++ }
        /Infected.*FOUND/                       { virus++ }
        /warning:/                              { warnings++ }
        /error:|fatal:/                         { errors++ }
        /postscreen.*PASS NEW/                  { ps_pass_new++ }
        /postscreen.*PASS OLD/                  { ps_pass_old++ }
        /postscreen.*NOQUEUE.*reject/           { ps_reject++ }
        /postscreen.*DNSBL/                     { ps_dnsbl++ }
        /postscreen.*PREGREET/                  { ps_pregreet++ }
        /postscreen.*HANGUP/                    { ps_hangup++ }
        /postscreen.*WHITELISTED/               { ps_whitelisted++ }
        /postscreen.*CONNECT/                   { ps_connect++ }
        END {
            print "SASL_AUTH_FAILED=" (sasl+0)
            print "RELAY_DENIED=" (relay+0)
            print "USER_UNKNOWN=" (user_unknown+0)
            print "RBL_REJECT=" (rbl+0)
            print "CONNECTION_TIMEOUT=" (conn_timeout+0)
            print "TLS_FAILED=" (tls+0)
            print "QUOTA_EXCEEDED=" (quota+0)
            print "SPAM_REJECTED=" (spam+0)
            print "VIRUS_FOUND=" (virus+0)
            print "WARNINGS=" (warnings+0)
            print "ERRORS=" (errors+0)
            print "POSTSCREEN_PASS_NEW=" (ps_pass_new+0)
            print "POSTSCREEN_PASS_OLD=" (ps_pass_old+0)
            print "POSTSCREEN_REJECT=" (ps_reject+0)
            print "POSTSCREEN_DNSBL=" (ps_dnsbl+0)
            print "POSTSCREEN_PREGREET=" (ps_pregreet+0)
            print "POSTSCREEN_HANGUP=" (ps_hangup+0)
            print "POSTSCREEN_WHITELISTED=" (ps_whitelisted+0)
            print "POSTSCREEN_CONNECT=" (ps_connect+0)
        }
    ')"

    # Active = at least 1 postscreen log entry
    if [ "$POSTSCREEN_CONNECT" -gt 0 ] || [ "$POSTSCREEN_PASS_NEW" -gt 0 ]; then
        POSTSCREEN_ACTIVE=1
    else
        POSTSCREEN_ACTIVE=0
    fi

    # Write JSON
    cat > "$CACHE_FILE" << EOFJSON
{
  "sasl_auth_failed": $SASL_AUTH_FAILED,
  "relay_denied": $RELAY_DENIED,
  "user_unknown": $USER_UNKNOWN,
  "rbl_reject": $RBL_REJECT,
  "connection_timeout": $CONNECTION_TIMEOUT,
  "tls_failed": $TLS_FAILED,
  "quota_exceeded": $QUOTA_EXCEEDED,
  "spam_rejected": $SPAM_REJECTED,
  "virus_found": $VIRUS_FOUND,
  "warnings": $WARNINGS,
  "errors": $ERRORS,
  "postscreen_active": $POSTSCREEN_ACTIVE,
  "postscreen_pass_new": $POSTSCREEN_PASS_NEW,
  "postscreen_pass_old": $POSTSCREEN_PASS_OLD,
  "postscreen_reject": $POSTSCREEN_REJECT,
  "postscreen_dnsbl": $POSTSCREEN_DNSBL,
  "postscreen_pregreet": $POSTSCREEN_PREGREET,
  "postscreen_hangup": $POSTSCREEN_HANGUP,
  "postscreen_whitelisted": $POSTSCREEN_WHITELISTED,
  "postscreen_connect": $POSTSCREEN_CONNECT
}
EOFJSON
}

# Check cache
if [ ! -f "$CACHE_FILE" ] || [ $(($(date +%s) - $(stat -c %Y "$CACHE_FILE" 2>/dev/null || echo 0))) -gt $CACHE_MAX_AGE ]; then
    update_cache
fi

# Read from cache
if command -v jq &>/dev/null; then
    cat "$CACHE_FILE" 2>/dev/null | jq -r ".${1} // 0" 2>/dev/null || echo 0
else
    grep -oP "\"$1\":\s*\K\d+" "$CACHE_FILE" 2>/dev/null || echo 0
fi
