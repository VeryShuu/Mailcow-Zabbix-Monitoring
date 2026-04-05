#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - JSON Reader
#  Version:    1.1
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Reads metrics from /var/tmp/mailcow-monitor.json
#               Called by Zabbix UserParameters - no privileges required
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
#  v1.1: jq replaces Python3 fork (~10x faster startup, no interpreter)
#        KEY passed via --arg to prevent shell injection
#        -rc: raw output for strings/numbers, compact JSON for arrays/objects
# ====================================================================

JSON_FILE="/var/tmp/mailcow-monitor.json"
KEY="$1"

if [ -z "$KEY" ]; then
    echo "Usage: $0 <key>"
    exit 1
fi

if [ ! -f "$JSON_FILE" ]; then
    echo "ZBX_NOTSUPPORTED: No data file"
    exit 1
fi

# Check if file is older than 5 minutes (collector not running)
FILE_AGE=$(( $(date +%s) - $(stat -c %Y "$JSON_FILE" 2>/dev/null || echo 0) ))
if [ "$FILE_AGE" -gt 300 ]; then
    echo "ZBX_NOTSUPPORTED: Data stale (${FILE_AGE}s)"
    exit 1
fi

# jq: KEY via --arg prevents shell injection; -rc = raw strings + compact JSON arrays
RESULT=$(jq -rc --arg k "$KEY" '.[$k] // empty' "$JSON_FILE" 2>/dev/null)

if [ -z "$RESULT" ]; then
    echo "ZBX_NOTSUPPORTED: Key not found"
    exit 1
fi

echo "$RESULT"
