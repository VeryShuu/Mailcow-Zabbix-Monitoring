#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - Common Shell Library
#  Version:    1.1
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Shared MySQL init and helper functions for check_*.sh scripts
#               Source this file: source /usr/local/bin/mailcow-common.sh
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================

MAILCOW_MONITOR_CONF="/etc/mailcow-monitor.conf"
[ -f "$MAILCOW_MONITOR_CONF" ] && source "$MAILCOW_MONITOR_CONF"
MAILCOW_DIR="${MAILCOW_DIR:-/opt/mailcow-dockerized}"

# Read DB password from mailcow.conf
DBPASS=$(grep -oP "DBPASS=\K[a-zA-Z0-9._-]+" "$MAILCOW_DIR/mailcow.conf" 2>/dev/null)

# Find MySQL/MariaDB container
MYSQL_CONTAINER=$(docker ps --filter "name=mysql" --format "{{.Names}}" 2>/dev/null | grep -i mailcow | head -1)
[ -z "$MYSQL_CONTAINER" ] && \
    MYSQL_CONTAINER=$(docker ps --filter "name=maria" --format "{{.Names}}" 2>/dev/null | grep -i mailcow | head -1)

# Execute a MySQL query via docker exec; password passed via env only (not on CLI)
_mysql() {
    docker exec -e "MYSQL_PWD=$DBPASS" "$MYSQL_CONTAINER" \
        mysql -u mailcow mailcow -Nse "$1" 2>/dev/null
}

# Get all active mail domains (excluding SOGo internal domains)
get_mail_domains() {
    if [ -z "$MYSQL_CONTAINER" ] || [ -z "$DBPASS" ]; then
        return 1
    fi
    _mysql "SELECT domain FROM domain WHERE active=1 AND domain NOT LIKE '%_sogo%'"
}
