#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - Open Relay Check
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Checks if mynetworks contains unsafe entries (0.0.0.0/0 or ::/0)
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
MAILCOW_MONITOR_CONF="/etc/mailcow-monitor.conf"
[ -f "$MAILCOW_MONITOR_CONF" ] && source "$MAILCOW_MONITOR_CONF"
MAILCOW_DIR="${MAILCOW_DIR:-/opt/mailcow-dockerized}"

# --- Find Postfix container ---
POSTFIX_CONTAINER=$(docker ps --filter "name=postfix" --format "{{.Names}}" 2>/dev/null | grep -i mailcow | head -1)

if [ -z "$POSTFIX_CONTAINER" ]; then
    # Postfix container not found → cannot check → report safe
    echo 0
    exit 0
fi

# --- Read mynetworks from Postfix ---
MYNETWORKS=$(docker exec "$POSTFIX_CONTAINER" postconf mynetworks 2>/dev/null)

if [ -z "$MYNETWORKS" ]; then
    # Cannot read postconf → report safe
    echo 0
    exit 0
fi

# --- Check for unsafe entries ---
# 0.0.0.0/0 = any IPv4 address may relay
# ::/0 = any IPv6 address may relay
if echo "$MYNETWORKS" | grep -qE '(0\.0\.0\.0/0|::/0)'; then
    # OPEN RELAY: unsafe mynetworks configuration!
    echo 1
    exit 0
fi

# --- Additional check: verify smtpd_recipient_restrictions ---
RECIPIENT_RESTRICTIONS=$(docker exec "$POSTFIX_CONTAINER" postconf smtpd_recipient_restrictions 2>/dev/null)

# If smtpd_recipient_restrictions is completely empty or contains only permit
if echo "$RECIPIENT_RESTRICTIONS" | grep -qE '^\s*smtpd_recipient_restrictions\s*=\s*permit\s*$'; then
    # Everything is allowed → open relay
    echo 1
    exit 0
fi

# All OK
echo 0
