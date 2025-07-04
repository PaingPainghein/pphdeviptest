#!/usr/bin/env bash
set -e

# Prompt for Domain Name and API Server IP
prompt_for_domain() {
    local default_domain="pphdev.udp.com"
    echo -n "Enter your IP or DNS for this server (default: $default_domain): "
    read -r input_domain
    DOMAIN=${input_domain:-$default_domain}
}

prompt_for_api_ip() {
    echo -n "Enter the IP address for the API server: "
    read -r api_ip
    if [[ -z "$api_ip" ]]; then
        error "API server IP is required."
        exit 1
    fi
    API_IP="$api_ip"
}

# Prompt for OBFS string
prompt_for_obfs() {
    local default_obfs="pphdev"
    echo -n "Enter the OBFS string (default: $default_obfs): "
    read -r input_obfs
    OBFS=${input_obfs:-$default_obfs}
}

# Values set by prompts
DOMAIN=""
OBFS=""
API_IP=""
PROTOCOL="udp"
UDP_PORT=":36712"
PASSWORD="agnudp"

# Script paths
SCRIPT_NAME="$(basename "$0")"
SCRIPT_ARGS=("$@")
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
SYSTEMD_SERVICES_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/hysteria"
SUBSCRIPTION_DB="$CONFIG_DIR/subscriptions.db"
CONFIG_FILE="$CONFIG_DIR/config.json"
API_SERVICE="$SYSTEMD_SERVICES_DIR/pphdev-api.service"
API_SCRIPT="/usr/local/bin/pphdev-api.py"
MANAGER_SCRIPT="/usr/local/bin/pphdev_vip_manager.sh"
SYMLINK_PATH="/usr/local/bin/pphdevvip"
REPO_URL="https://github.com/apernet/hysteria"
API_BASE_URL="https://api.github.com/repos/apernet/hysteria"
CURL_FLAGS=(-L -f -q --retry 5 --retry-delay 10 --retry-max-time 60)
mkdir -p "$CONFIG_DIR"
touch "$SUBSCRIPTION_DB"

# Other configurations
OPERATING_SYSTEM=""
ARCHITECTURE=""
HYSTERIA_USER=""
HYSTERIA_HOME_DIR=""
VERSION=""
FORCE=""
LOCAL_FILE=""
FORCE_NO_ROOT=""
FORCE_NO_SYSTEMD=""

# Utility functions (unchanged from original for brevity, assume included as in the original script)
has_command() { type -P "$1" > /dev/null 2>&1; }
curl() { command curl "${CURL_FLAGS[@]}" "$@"; }
mktemp() { command mktemp "$@" "hyservinst.XXXXXXXXXX"; }
tput() { if has_command tput; then command tput "$@"; fi; }
tred() { tput setaf 1; }
tgreen() { tput setaf 2; }
tyellow() { tput setaf 3; }
tblue() { tput setaf 4; }
tbold() { tput bold; }
treset() { tput sgr0; }
note() { echo -e "$SCRIPT_NAME: $(tbold)note: $1$(treset)"; }
warning() { echo -e "$SCRIPT_NAME: $(tyellow)warning: $1$(treset)"; }
error() { echo -e "$SCRIPT_NAME: $(tred)error: $1$(treset)"; }
show_argument_error_and_exit() { error "$1"; echo "Try \"$0 --help\" for the usage." >&2; exit 22; }
install_content() {
    local _install_flags="$1" _content="$2" _destination="$3" _tmpfile="$(mktemp)"
    echo -ne "Install $_destination ... "
    echo "$_content" > "$_tmpfile"
    if install "$_install_flags" "$_tmpfile" "$_destination"; then echo -e "ok"; fi
    rm -f "$_tmpfile"
}
remove_file() { local _target="$1"; echo -ne "Remove $_target ... "; if rm "$_target"; then echo -e "ok"; fi; }
install_software() {
    local package="$1"
    if has_command apt-get; then apt-get update && apt-get install -y "$package"
    elif has_command dnf; then dnf install -y "$package"
    elif has_command yum; then yum install -y "$package"
    elif has_command zypper; then zypper install -y "$package"
    elif has_command pacman; then pacman -Sy --noconfirm "$package"
    else error "No supported package manager found. Please install $package manually."; exit 1; fi
}
check_permission() {
    if [[ "$UID" -eq '0' ]]; then return; fi
    if has_command sudo; then exec_sudo "$0" "${SCRIPT_ARGS[@]}"; else error "Please run as root or specify FORCE_NO_ROOT=1."; exit 13; fi
}
check_environment_operating_system() { if [[ "x$(uname)" == "xLinux" ]]; then OPERATING_SYSTEM=linux; else error "This script only supports Linux."; exit 95; fi; }
check_environment_architecture() {
    case "$(uname -m)" in
        'i386' | 'i686') ARCHITECTURE='386' ;;
        'amd64' | 'x86_64') ARCHITECTURE='amd64' ;;
        'armv5tel' | 'armv6l' | 'armv7' | 'armv7l') ARCHITECTURE='arm' ;;
        'armv8' | 'aarch64') ARCHITECTURE='arm64' ;;
        *) error "Architecture '$(uname -m)' not supported."; exit 8 ;;
    esac
}
check_environment_systemd() { if [[ -d "/run/systemd/system" ]]; then return; fi; error "This script requires systemd."; exit 1; }
check_environment() {
    check_environment_operating_system
    check_environment_architecture
    check_environment_systemd
    for cmd in curl grep sqlite3 python3 pip3; do if ! has_command "$cmd"; then install_software "$cmd"; fi; done
}

# Setup SQLite database for subscriptions
setup_db() {
    echo "Setting up subscription database..."
    sqlite3 "$SUBSCRIPTION_DB" <<EOF
CREATE TABLE IF NOT EXISTS subscriptions (
    name TEXT,
    key TEXT PRIMARY KEY,
    valid INTEGER NOT NULL,
    expiration TEXT NOT NULL,
    token TEXT NOT NULL
);
INSERT OR IGNORE INTO subscriptions (name, key, valid, expiration, token) 
VALUES ('Default User', '$(uuidgen)', 30, '2025-12-31', '$(uuidgen)');
EOF
    chmod 644 "$SUBSCRIPTION_DB"
    echo -e "Database setup completed."
}

# Setup Flask API server
setup_api_server() {
    echo "Installing Flask API server..."
    pip3 install flask flask-jwt-extended
    cat > "$API_SCRIPT" << 'EOF'
#!/usr/bin/env python3
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
import sqlite3
import datetime
import os

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
jwt = JWTManager(app)
DB_PATH = '/etc/hysteria/subscriptions.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/pphdev/check', methods=['GET'])
@jwt_required()
def check_subscription():
    key = request.args.get('key')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name, key, valid, expiration FROM subscriptions WHERE key = ? OR token = ?", (key, key))
    sub = cursor.fetchone()
    conn.close()
    if sub and sub['valid'] > 0:
        return jsonify([{
            'Name': sub['name'],
            'Key': sub['key'],
            'Valid': str(sub['valid']),
            'Expiration': sub['expiration']
        }]), 200
    return jsonify([]), 200

@app.route('/pphdev/update', methods=['POST'])
@jwt_required()
def update_subscription():
    key = request.args.get('key')
    name = request.args.get('name')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE subscriptions SET name = ? WHERE key = ? OR token = ?", (name, key, key))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'}), 200

@app.route('/pphdev/delete', methods=['POST'])
@jwt_required()
def delete_subscription():
    key = request.args.get('key')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM subscriptions WHERE key = ? OR token = ?", (key, key))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'}), 200

@app.route('/pphdev/set_expiration', methods=['POST'])
@jwt_required()
def set_expiration():
    key = request.args.get('key')
    expiration = request.args.get('expiration')
    try:
        datetime.datetime.strptime(expiration, '%Y-%m-%d')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE subscriptions SET expiration = ?, valid = ((julianday(?) - julianday('now')) + 1) WHERE key = ? OR token = ?", 
                      (expiration, expiration, key, key))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'}), 200
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

@app.route('/pphdev/add', methods=['POST'])
@jwt_required()
def add_subscription():
    data = request.get_json()
    name = data.get('name')
    key = data.get('key')
    valid = data.get('valid')
    expiration = data.get('expiration')
    token = data.get('token')
    try:
        datetime.datetime.strptime(expiration, '%Y-%m-%d')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO subscriptions (name, key, valid, expiration, token) VALUES (?, ?, ?, ?, ?)", 
                      (name, key, valid, expiration, token))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'}), 200
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Key already exists'}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF
    chmod +x "$API_SCRIPT"
    cat > "$API_SERVICE" <<EOF
[Unit]
Description=PPHdev Subscription API Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 $API_SCRIPT
Restart=always
User=root
Environment="JWT_SECRET_KEY=your-secret-key"

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable pphdev-api.service
    systemctl start pphdev-api.service
    echo -e "Flask API server installed and started."
}

# Install manager script
perform_install_manager_script() {
    echo "Downloading updated manager script..."
    curl -o "$MANAGER_SCRIPT" "https://raw.githubusercontent.com/PaingPainghein/pphdeviptest/refs/heads/main/pphdev_vip_manager"
    chmod +x "$MANAGER_SCRIPT"
    ln -sf "$MANAGER_SCRIPT" "$SYMLINK_PATH"
    echo "Manager script installed at $MANAGER_SCRIPT"
    echo "Run it using 'pphdevvip' command."
}

# Hysteria configuration (simplified, assuming unchanged from original except for users)
tpl_etc_hysteria_config_json() {
    cat << EOF > "$CONFIG_FILE"
{
  "server": "$DOMAIN",
  "listen": "$UDP_PORT",
  "protocol": "$PROTOCOL",
  "cert": "/etc/hysteria/hysteria.server.crt",
  "key": "/etc/hysteria/hysteria.server.key",
  "up": "100 Mbps",
  "up_mbps": 100,
  "down": "100 Mbps",
  "down_mbps": 100,
  "disable_udp": false,
  "insecure": false,
  "obfs": "$OBFS",
  "auth": {
    "mode": "passwords",
    "config": []
  }
}
EOF
}

# Setup SSL certificates
setup_ssl() {
    echo "Installing SSL certificates..."
    openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048
    openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" -out /etc/hysteria/hysteria.ca.crt
    openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$DOMAIN" -out /etc/hysteria/hysteria.server.csr
    openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:$DOMAIN") -days 3650 -in /etc/hysteria/hysteria.server.csr -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key -set_serial 01 -out /etc/hysteria/hysteria.server.crt
}

# Start services
start_services() {
    echo "Starting services..."
    apt update
    apt -y install iptables-persistent
    iptables -t nat -A PREROUTING -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
    ip6tables -t nat -A PREROUTING -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
    sysctl net.ipv4.conf.all.rp_filter=0
    sysctl net.ipv4.conf.$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1).rp_filter=0
    echo "net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1).rp_filter=0" > /etc/sysctl.conf
    sysctl -p
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    systemctl enable hysteria-server.service
    systemctl start hysteria-server.service
}

# Install Hysteria binary (unchanged, assume included as in original)
perform_install_hysteria_binary() {
    local _tmpfile=$(mktemp)
    if ! curl -R -H 'Cache-Control: no-cache' "$REPO_URL/releases/download/v1.3.5/hysteria-$OPERATING_SYSTEM-$ARCHITECTURE" -o "$_tmpfile"; then
        rm -f "$_tmpfile"
        error "Download failed! Check your network."
        exit 11
    fi
    install -Dm755 "$_tmpfile" "$EXECUTABLE_INSTALL_PATH"
    rm -f "$_tmpfile"
}

# Systemd service configuration
tpl_hysteria_server_service() {
    cat << EOF
[Unit]
Description=PPHdev UDP Service
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/etc/hysteria
Environment="PATH=/usr/local/bin/hysteria"
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.json

[Install]
WantedBy=multi-user.target
EOF
}

perform_install() {
    perform_install_hysteria_binary
    setup_db
    tpl_etc_hysteria_config_json
    setup_ssl
    setup_api_server
    install_content -Dm644 "$(tpl_hysteria_server_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
    systemctl daemon-reload
    perform_install_manager_script
    start_services
    echo -e "\e[1;32mPPHdev UDP installed successfully!\e[0m"
    echo -e "API server running at http://$API_IP:5000"
    echo -e "Use 'pphdevvip' to manage subscriptions."
}

main() {
    check_environment
    prompt_for_domain
    prompt_for_obfs
    prompt_for_api_ip
    perform_install
}

main "$@"
