#!/bin/bash

# Removal script for PPH VIP Manager
echo -e "\e[1;34m=== Removing PPH VIP Manager Components ===\e[0m"

# Define paths
CONFIG_DIR="/etc/hysteria"
SYSTEMD_SERVICE="/etc/systemd/system/hysteria-server.service"
SYSTEMD_SERVICE_X="/etc/systemd/system/hysteria-server@.service"
WEB_SERVICE_FILE="/etc/systemd/system/udp-web-status.service"
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
MANAGER_SCRIPT="/usr/local/bin/pphdev_udp_manager.sh"
SYMLINK_PATH="/usr/local/bin/pphdevudp"
WEB_DIR="/var/www/html/udpserver"
LOG_FILE="/var/log/hysteria/hysteria.log"
ONLINE_USERS_FILE="$CONFIG_DIR/online_users.log"
WEB_STATUS_FILE="$WEB_DIR/online"
WEB_STATUS_ENABLED="$CONFIG_DIR/web_status_enabled"
TRACKER_PID_FILE="$CONFIG_DIR/.tracker_pid"
USER_DB="$CONFIG_DIR/udpusers.db"

# Stop and disable services
echo -e "\e[1;34mStopping and disabling services...\e[0m"
systemctl stop hysteria-server 2>/dev/null
systemctl disable hysteria-server 2>/dev/null
systemctl stop udp-web-status 2>/dev/null
systemctl disable udp-web-status 2>/dev/null
systemctl stop nginx 2>/dev/null
systemctl disable nginx 2>/dev/null

# Remove systemd service files
echo -e "\e[1;34mRemoving systemd service files...\e[0m"
rm -f "$SYSTEMD_SERVICE" "$SYSTEMD_SERVICE_X" "$WEB_SERVICE_FILE"
systemctl daemon-reload

# Stop any running monitoring processes
if [[ -f "$TRACKER_PID_FILE" ]]; then
    pid=$(cat "$TRACKER_PID_FILE")
    if ps -p "$pid" > /dev/null 2>&1; then
        kill "$pid"
        echo -e "\e[1;32mStopped monitoring process (PID $pid).\e[0m"
    fi
    rm -f "$TRACKER_PID_FILE"
fi
pkill -f "journalctl -u hysteria-server -f --no-pager" 2>/dev/null
pkill -f "netstat.*$CONFIG_DIR" 2>/dev/null
pkill -f "ss.*$CONFIG_DIR" 2>/dev/null

# Remove configuration directory and files
echo -e "\e[1;34mRemoving configuration files...\e[0m"
rm -rf "$CONFIG_DIR"

# Remove web directory and status files
echo -e "\e[1;34mRemoving web directory and status files...\e[0m"
rm -rf "$WEB_DIR"
rm -f "$WEB_STATUS_ENABLED"

# Remove log file
echo -e "\e[1;34mRemoving log file...\e[0m"
rm -f "$LOG_FILE"

# Remove executable and manager script
echo -e "\e[1;34mRemoving executable and manager script...\e[0m"
rm -f "$EXECUTABLE_INSTALL_PATH" "$MANAGER_SCRIPT" "$SYMLINK_PATH"

# Remove Nginx configuration
echo -e "\e[1;34mRemoving Nginx configuration...\e[0m"
rm -f /etc/nginx/sites-enabled/udp-status
rm -f /etc/nginx/sites-available/udp-status
systemctl reload nginx 2>/dev/null

# Remove iptables rules
echo -e "\e[1;34mRemoving iptables rules...\e[0m"
iptables -t nat -F PREROUTING 2>/dev/null
ip6tables -t nat -F PREROUTING 2>/dev/null
iptables-save > /etc/iptables/rules.v4 2>/dev/null
ip6tables-save > /etc/iptables/rules.v6 2>/dev/null

echo -e "\e[1;32mPPH VIP Manager components removed successfully!\e[0m"
