#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - Security Audit Check
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Checks DANE/TLSA, MTA-STS, TLS-RPT, BIMI for all domains
#  Usage:      check_security_audit.sh [dane|mta_sts|tls_rpt|bimi|detail|score]
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================

source /usr/local/bin/mailcow-common.sh
CHECK_TYPE="${1:-detail}"

# --- Mailcow hostname and domains ---
get_hostname() {
    grep -oP "^MAILCOW_HOSTNAME=\K[a-zA-Z0-9._-]+" "$MAILCOW_DIR/mailcow.conf" 2>/dev/null
}

get_domains() {
    get_mail_domains
}

# --- DANE/TLSA: _25._tcp.hostname ---
# TLSA records prove that the TLS certificate matches the DNS entry
check_dane() {
    local hostname="$1"
    timeout 5 dig +short +time=3 +tries=1 TLSA "_25._tcp.${hostname}" 2>/dev/null | grep -q "^[0-9]"
    # Return: 0=found, 1=not found
    [ $? -eq 0 ] && echo 1 || echo 0
}

# --- MTA-STS: _mta-sts.domain TXT + policy file ---
# Enforces TLS for incoming mail (similar to HSTS for SMTP)
check_mta_sts() {
    local domain="$1"
    # Step 1: DNS TXT record
    local txt
    txt=$(timeout 5 dig +short +time=3 +tries=1 TXT "_mta-sts.${domain}" 2>/dev/null)
    if ! echo "$txt" | grep -q "v=STSv1"; then
        echo 0
        return
    fi
    # Step 2: Policy file reachable via HTTPS
    if command -v curl >/dev/null 2>&1; then
        if curl -sf --max-time 5 \
                "https://mta-sts.${domain}/.well-known/mta-sts.txt" \
                2>/dev/null | grep -q "version: STSv1"; then
            echo 1
            return
        fi
        echo 0
        return
    fi
    # curl not available — DNS record alone is sufficient signal
    echo 1
}

# --- TLS-RPT: _smtp._tls.domain ---
# Receives reports about TLS errors on incoming connections
check_tls_rpt() {
    local domain="$1"
    timeout 5 dig +short +time=3 +tries=1 TXT "_smtp._tls.${domain}" 2>/dev/null | grep -q "v=TLSRPTv1"
    [ $? -eq 0 ] && echo 1 || echo 0
}

# --- BIMI: default._bimi.domain ---
# Brand logo in email clients (requires DMARC p=quarantine/reject)
check_bimi() {
    local domain="$1"
    timeout 5 dig +short +time=3 +tries=1 TXT "default._bimi.${domain}" 2>/dev/null | grep -q "v=BIMI1"
    [ $? -eq 0 ] && echo 1 || echo 0
}

# --- Main ---
HOSTNAME=$(get_hostname)
DOMAINS=$(get_domains)

if [ -z "$DOMAINS" ]; then
    # Fallback: domain from hostname
    DOMAINS=$(echo "$HOSTNAME" | sed 's/^[^.]*//' | sed 's/^\.//')
fi

case "$CHECK_TYPE" in
    dane)
        # DANE is only checked on the MX hostname (not per domain)
        if [ -n "$HOSTNAME" ]; then
            check_dane "$HOSTNAME"
        else
            echo 0
        fi
        ;;
    mta_sts)
        ALL_OK=1
        for domain in $DOMAINS; do
            result=$(check_mta_sts "$domain")
            [ "$result" != "1" ] && ALL_OK=0
        done
        echo "$ALL_OK"
        ;;
    tls_rpt)
        ALL_OK=1
        for domain in $DOMAINS; do
            result=$(check_tls_rpt "$domain")
            [ "$result" != "1" ] && ALL_OK=0
        done
        echo "$ALL_OK"
        ;;
    bimi)
        ALL_OK=1
        for domain in $DOMAINS; do
            result=$(check_bimi "$domain")
            [ "$result" != "1" ] && ALL_OK=0
        done
        echo "$ALL_OK"
        ;;
    score)
        # Total score: 0-7 (SPF+DKIM+DMARC+DANE+MTA-STS+TLS-RPT+BIMI)
        SCORE=0

        # SPF/DKIM/DMARC from existing check_dns.sh
        SPF=$(/usr/local/bin/check_dns.sh spf 2>/dev/null)
        DKIM=$(/usr/local/bin/check_dns.sh dkim 2>/dev/null)
        DMARC=$(/usr/local/bin/check_dns.sh dmarc 2>/dev/null)
        [ "$SPF" = "1" ] && SCORE=$((SCORE + 1))
        [ "$DKIM" = "1" ] && SCORE=$((SCORE + 1))
        [ "$DMARC" = "1" ] && SCORE=$((SCORE + 1))

        # Additional checks
        [ -n "$HOSTNAME" ] && [ "$(check_dane "$HOSTNAME")" = "1" ] && SCORE=$((SCORE + 1))

        MTA_OK=1; TLS_OK=1; BIMI_OK=1
        for domain in $DOMAINS; do
            [ "$(check_mta_sts "$domain")" != "1" ] && MTA_OK=0
            [ "$(check_tls_rpt "$domain")" != "1" ] && TLS_OK=0
            [ "$(check_bimi "$domain")"    != "1" ] && BIMI_OK=0
        done
        [ "$MTA_OK"  = "1" ] && SCORE=$((SCORE + 1))
        [ "$TLS_OK"  = "1" ] && SCORE=$((SCORE + 1))
        [ "$BIMI_OK" = "1" ] && SCORE=$((SCORE + 1))

        echo "$SCORE"
        ;;
    detail)
        # Detailed output per domain
        RESULTS=""

        # DANE (hostname-level)
        if [ -n "$HOSTNAME" ]; then
            DANE_RESULT=$(check_dane "$HOSTNAME")
            [ "$DANE_RESULT" != "1" ] && RESULTS="${RESULTS}${HOSTNAME}:DANE_missing,"
        fi

        for domain in $DOMAINS; do
            MISSING=""
            [ "$(check_mta_sts "$domain")" != "1" ] && MISSING="${MISSING}MTA-STS "
            [ "$(check_tls_rpt "$domain")" != "1" ] && MISSING="${MISSING}TLS-RPT "
            [ "$(check_bimi "$domain")" != "1" ] && MISSING="${MISSING}BIMI "

            if [ -n "$MISSING" ]; then
                RESULTS="${RESULTS}${domain}:${MISSING% },"
            fi
        done

        if [ -n "$RESULTS" ]; then
            echo "${RESULTS%,}"
        else
            echo "OK"
        fi
        ;;
    *)
        echo "Usage: $0 [dane|mta_sts|tls_rpt|bimi|detail|score]"
        exit 1
        ;;
esac
