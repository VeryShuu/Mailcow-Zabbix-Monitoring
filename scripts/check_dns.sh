#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - DNS Record Check
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Checks SPF/DKIM/DMARC for all active mail domains
#  Usage:      check_dns.sh [spf|dkim|dmarc|detail|domains]
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================

source /usr/local/bin/mailcow-common.sh
CHECK_TYPE="${1:-detail}"

# --- Get all active mail domains from MySQL ---
get_domains() {
    get_mail_domains
}

# --- Check SPF for a domain ---
check_spf() {
    local domain="$1"
    timeout 5 dig +short +time=2 +tries=1 TXT "$domain" 2>/dev/null | grep -q "v=spf1"
    echo $?
}

# --- Check DKIM for a domain ---
check_dkim() {
    local domain="$1"
    local selectors=""

    # Query actual selector from DB first (Mailcow stores it in dkim table)
    if [ -n "$MYSQL_CONTAINER" ] && [ -n "$DBPASS" ]; then
        local db_selector domain_esc
        domain_esc=$(printf '%s' "$domain" | sed "s/'/\\\\'/g")
        db_selector=$(_mysql "SELECT selector FROM dkim WHERE domain='${domain_esc}' LIMIT 1" 2>/dev/null)
        [ -n "$db_selector" ] && selectors="$db_selector"
    fi

    # Append fallback selectors (avoid duplicates)
    for s in dkim mail default s1; do
        echo "$selectors" | grep -qxF "$s" || selectors="$selectors $s"
    done

    for selector in $selectors; do
        [ -z "$selector" ] && continue
        if timeout 5 dig +short +time=2 +tries=1 TXT "${selector}._domainkey.${domain}" 2>/dev/null | grep -q "v=DKIM1"; then
            echo 0
            return
        fi
    done
    echo 1
}

# --- Check DMARC for a domain ---
check_dmarc() {
    local domain="$1"
    timeout 5 dig +short +time=2 +tries=1 TXT "_dmarc.${domain}" 2>/dev/null | grep -q "v=DMARC1"
    echo $?
}

# --- Main ---
DOMAINS=$(get_domains)

if [ -z "$DOMAINS" ]; then
    # Fallback: try hostname domain
    HOSTNAME_DOMAIN=$(grep -oP "^MAILCOW_HOSTNAME=\K[a-zA-Z0-9._-]+" "$MAILCOW_DIR/mailcow.conf" 2>/dev/null)
    # Extract base domain (cow.fox1.de -> fox1.de)
    DOMAINS=$(echo "$HOSTNAME_DOMAIN" | sed 's/^[^.]*\.//')
fi

case "$CHECK_TYPE" in
    domains)
        echo "$DOMAINS" | tr '\n' ' '
        ;;
    spf)
        FAIL=0
        for domain in $DOMAINS; do
            result=$(check_spf "$domain")
            [ "$result" != "0" ] && FAIL=$((FAIL + 1))
        done
        # Return 1 (OK) if no failures, 0 if any failures
        [ "$FAIL" -eq 0 ] && echo 1 || echo 0
        ;;
    dkim)
        FAIL=0
        for domain in $DOMAINS; do
            result=$(check_dkim "$domain")
            [ "$result" != "0" ] && FAIL=$((FAIL + 1))
        done
        [ "$FAIL" -eq 0 ] && echo 1 || echo 0
        ;;
    dmarc)
        FAIL=0
        for domain in $DOMAINS; do
            result=$(check_dmarc "$domain")
            [ "$result" != "0" ] && FAIL=$((FAIL + 1))
        done
        [ "$FAIL" -eq 0 ] && echo 1 || echo 0
        ;;
    detail)
        ISSUES=""
        for domain in $DOMAINS; do
            spf=$(check_spf "$domain")
            dkim=$(check_dkim "$domain")
            dmarc=$(check_dmarc "$domain")
            
            MISSING=""
            [ "$spf" != "0" ] && MISSING="${MISSING}SPF "
            [ "$dkim" != "0" ] && MISSING="${MISSING}DKIM "
            [ "$dmarc" != "0" ] && MISSING="${MISSING}DMARC "
            
            if [ -n "$MISSING" ]; then
                ISSUES="${ISSUES}${domain}:${MISSING% },"
            fi
        done
        
        if [ -n "$ISSUES" ]; then
            echo "${ISSUES%,}"
        else
            echo "OK"
        fi
        ;;
    *)
        echo "Usage: $0 [spf|dkim|dmarc|detail|domains]"
        exit 1
        ;;
esac
