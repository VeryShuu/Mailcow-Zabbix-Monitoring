#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - Uninstaller
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Removes Collector, Reader, Configs and systemd Units
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo ""
echo "============================================="
echo " Mailcow Monitoring v1.0 - Uninstall"
echo "============================================="
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ Please run as root!${NC}"
    exit 1
fi

read -p "Remove Mailcow Monitoring completely? (y/n): " -n 1 -r
echo ""
[[ ! $REPLY =~ ^[YyJj]$ ]] && { echo "Aborted."; exit 0; }

# 1. Stop systemd timer/service
echo -e "${YELLOW}[1/6] Stopping systemd units...${NC}"
systemctl stop mailcow-monitor.timer 2>/dev/null || true
systemctl disable mailcow-monitor.timer 2>/dev/null || true
systemctl stop mailcow-monitor.service 2>/dev/null || true
rm -f /etc/systemd/system/mailcow-monitor.timer
rm -f /etc/systemd/system/mailcow-monitor.service
systemctl daemon-reload
echo -e "${GREEN}✓ systemd units removed${NC}"

# 2. Collector & Reader & Helper
echo -e "${YELLOW}[2/6] Removing scripts...${NC}"
rm -f /usr/local/bin/mailcow-collector.py
rm -f /usr/local/bin/mailcow-reader.sh
for S in check_rbl.sh check_dns.sh check_tls.sh check_ptr.sh check_open_relay.sh \
         check_security_audit.sh mailcow-common.sh \
         dovecot_check.sh sync_jobs_check.sh postfix_stats_docker.sh \
         postfix_log_analysis.sh check_postfix_running.sh check_mailcow_ui.sh \
         check_agent_uptime.sh check_backup_age.sh check_backup_size.sh \
         check_backup_zero.sh rspamd_stats.sh; do
    rm -f "/usr/local/bin/$S"
done
echo -e "${GREEN}✓ Scripts removed${NC}"

# 3. Zabbix Agent Config
echo -e "${YELLOW}[3/6] Removing Zabbix config...${NC}"
rm -f /etc/zabbix/zabbix_agent2.d/mailcow*.conf
echo -e "${GREEN}✓ UserParameter configs removed${NC}"

# 4. Sudoers
echo -e "${YELLOW}[4/6] Removing sudoers...${NC}"
rm -f /etc/sudoers.d/zabbix-mailcow
echo -e "${GREEN}✓ Sudoers removed${NC}"

# 5. Cache/JSON + monitor config
echo -e "${YELLOW}[5/6] Removing cache and config...${NC}"
rm -f /var/tmp/mailcow-monitor.json
rm -f /var/tmp/mailcow-monitor.json.tmp
rm -f /var/tmp/mailcow-monitor-slow.json
rm -f /var/tmp/mailcow-monitor-mailflow.json
rm -f /var/tmp/mailcow-monitor-version.json
rm -f /var/tmp/postfix_log_analysis.cache /var/tmp/dovecot_check.cache
rm -f /var/tmp/rbl_check.cache /var/tmp/rspamd_stats.cache /var/tmp/rbl_check_detail.cache
rm -f /var/tmp/ptr_check.cache
rm -f /etc/mailcow-monitor.conf
echo -e "${GREEN}✓ Cache and /etc/mailcow-monitor.conf removed${NC}"

# 6. Restart Zabbix Agent
echo -e "${YELLOW}[6/6] Restarting Zabbix Agent...${NC}"
systemctl restart zabbix-agent2 2>/dev/null && \
    echo -e "${GREEN}✓ Zabbix Agent 2 restarted${NC}" || \
    echo -e "${YELLOW}! Zabbix Agent 2 could not be restarted${NC}"

echo ""
echo "============================================="
echo -e "${GREEN} Uninstall complete.${NC}"
echo "============================================="
echo ""
echo "  Backups: /root/mailcow-monitoring-backup-*"
echo "  Remove Zabbix template manually:"
echo "    Data collection → Templates → Mailcow Complete Monitoring v1.0 → Unlink/Delete"
echo ""
