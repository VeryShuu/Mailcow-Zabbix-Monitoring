#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - Sync Jobs Check
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Monitors Mailcow IMAP Sync Jobs (built-in migration)
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
source /usr/local/bin/mailcow-common.sh

if [ ! -f "$MAILCOW_DIR/mailcow.conf" ]; then
    echo "0"
    exit 0
fi

if [ -z "$DBPASS" ] || [ -z "$MYSQL_CONTAINER" ]; then
    echo "0"
    exit 0
fi

_mysql_sync() {
    _mysql "$1" || echo 0
}

case "$1" in
    active)
        _mysql_sync "SELECT COUNT(*) FROM imapsync WHERE active=1;"
        ;;
    running)
        _mysql_sync "SELECT COUNT(*) FROM imapsync WHERE is_running=1;"
        ;;
    failed)
        _mysql_sync "SELECT COUNT(*) FROM imapsync WHERE (returned_text LIKE '%error%' OR returned_text LIKE '%fail%' OR returned_text LIKE '%died%') AND last_run > DATE_SUB(NOW(), INTERVAL 24 HOUR);"
        ;;
    never_run)
        _mysql_sync "SELECT COUNT(*) FROM imapsync WHERE active=1 AND last_run IS NULL;"
        ;;
    oldest_run)
        _mysql_sync "SELECT COALESCE(TIMESTAMPDIFF(HOUR, MAX(last_run), NOW()), 0) FROM imapsync WHERE active=1 AND last_run IS NOT NULL;"
        ;;
    stuck)
        _mysql_sync "SELECT COUNT(*) FROM imapsync WHERE is_running=1 AND last_run < DATE_SUB(NOW(), INTERVAL 24 HOUR);"
        ;;
    *)
        echo 0
        ;;
esac
