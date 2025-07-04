#!/bin/bash

# Variables
USER_DB="/etc/hysteria/udpusers.db"
CONFIG_FILE="/etc/hysteria/config.json"
ONLINE_USERS_FILE="/var/log/hysteria_online_users.log"
HYSTERIA_VERSION="v2.0.0"
FLASK_PORT=5000
NGINX_PORT=82

# Check if command exists
has_command() {
    command -v "$1" >/dev/null 2>&1
}

# Install required software
install_software() {
    local pkg=$1
    if ! has_command "$pkg"; then
        echo "Installing $pkg..."
        apt-get update
        apt-get install -y "$pkg"
    fi
}

# Install Hysteria binary
perform_install_hysteria_binary() {
    echo "Installing Hysteria binary..."
    if ! has_command hysteria-server; then
        wget -qO /tmp/hysteria "https://github.com/HyNetwork/hysteria/releases/download/$HYSTERIA_VERSION/hysteria-linux-amd64"
        chmod +x /tmp/hysteria
        mv /tmp/hysteria /usr/local/bin/hysteria-server
    fi
}

# Install Hysteria example config
perform_install_hysteria_example_config() {
    echo "Creating Hysteria config..."
    mkdir -p /etc/hysteria
    cat > "$CONFIG_FILE" << EOF
{
    "listen": ":443",
    "protocol": "udp",
    "auth": {
        "mode": "passwords",
        "config": []
    },
    "tls": {
        "cert": "/etc/hysteria/server.crt",
        "key": "/etc/hysteria/server.key"
    }
}
EOF
}

# Install Hysteria systemd service
perform_install_hysteria_systemd() {
    echo "Setting up Hysteria systemd service..."
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria VPN Server
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria-server -config /etc/hysteria/config.json
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable hysteria-server
}

# Setup SQLite database
setup_db() {
    echo "Setting up database..."
    mkdir -p "$(dirname "$USER_DB")"
    if [[ ! -f "$USER_DB" ]]; then
        sqlite3 "$USER_DB" ".databases"
        if [[ $? -ne 0 ]]; then
            echo "Error: Unable to create database file at $USER_DB"
            exit 1
        fi
    fi

    sqlite3 "$USER_DB" << EOF
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    key TEXT UNIQUE NOT NULL,
    valid_days INTEGER NOT NULL,
    expiration_date TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS online_sessions (
    id INTEGER PRIMARY KEY,
    key TEXT,
    ip_address TEXT,
    connect_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    disconnect_time DATETIME,
    status TEXT DEFAULT 'online',
    FOREIGN KEY(key) REFERENCES subscriptions(key)
);
EOF
}

# Install Flask API
install_flask_api() {
    echo "Installing Flask API..."
    if ! has_command pip; then
        install_software "python3-pip"
    fi
    pip install flask
    cat > /etc/hysteria/app.py << EOF
from flask import Flask, jsonify, request
import sqlite3
from datetime import datetime

app = Flask(__name__)
USER_DB = "/etc/hysteria/udpusers.db"

def get_db():
    conn = sqlite3.connect(USER_DB)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/api/subscription', methods=['GET'])
def get_subscription():
    key = request.args.get('key')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name, key, valid_days, expiration_date FROM subscriptions WHERE key = ?", (key,))
    sub = cursor.fetchone()
    conn.close()
    
    if sub and datetime.strptime(sub['expiration_date'], '%Y-%m-%d %H:%M:%S') > datetime.now():
        return jsonify({
            'status': 'valid',
            'name': sub['name'],
            'key': sub['key'],
            'valid_days': sub['valid_days'],
            'expiration_date': sub['expiration_date']
        })
    return jsonify({'status': 'invalid'}), 404

@app.route('/api/subscription', methods=['POST'])
def add_subscription():
    data = request.get_json()
    name = data.get('name')
    key = data.get('key')
    valid_days = data.get('valid_days')
    expiration_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO subscriptions (name, key, valid_days, expiration_date) VALUES (?, ?, ?, ?)",
                   (name, key, valid_days, expiration_date))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'}), 201

@app.route('/api/subscription', methods=['PUT'])
def update_subscription():
    data = request.get_json()
    key = data.get('key')
    name = data.get('name')
    valid_days = data.get('valid_days')
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE subscriptions SET name = ?, valid_days = ?, expiration_date = ? WHERE key = ?",
                   (name, valid_days, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), key))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/subscription', methods=['DELETE'])
def delete_subscription():
    key = request.args.get('key')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM subscriptions WHERE key = ?", (key,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=$FLASK_PORT)
EOF
    chmod +x /etc/hysteria/app.py

    cat > /etc/systemd/system/udp-api.service << EOF
[Unit]
Description=UDP Subscription API
After=network.target

[Service]
ExecStart=/usr/bin/python3 /etc/hysteria/app.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable udp-api
    systemctl start udp-api
}

# Setup Nginx
setup_nginx() {
    echo "Setting up Nginx..."
    install_software "nginx"
    cat > /etc/nginx/sites-available/udp-api << EOF
server {
    listen $NGINX_PORT;
    server_name _;
    
    location /api/ {
        proxy_pass http://localhost:$FLASK_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
    ln -sf /etc/nginx/sites-available/udp-api /etc/nginx/sites-enabled/
    nginx -t && systemctl restart nginx
}

# Setup SSL (self-signed for testing)
setup_ssl() {
    echo "Setting up SSL..."
    if [[ ! -f /etc/hysteria/server.crt ]]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/hysteria/server.key \
            -out /etc/hysteria/server.crt \
            -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"
    fi
}

# Start services
start_services() {
    echo "Starting services..."
    systemctl start hysteria-server
    systemctl start udp-api
    systemctl start nginx
}

# Install manager script
perform_install_manager_script() {
    echo "Installing PPH VIP Manager script..."
    curl -o /usr/local/bin/pphdev_vip_manager.sh "https://raw.githubusercontent.com/PaingPainghein/pphdeviptest/main/pphdev_vip_manager.sh"
    chmod +x /usr/local/bin/pphdev_vip_manager.sh
}

# Main install function
perform_install() {
    perform_install_hysteria_binary
    perform_install_hysteria_example_config
    perform_install_hysteria_systemd
    setup_db
    install_flask_api
    setup_nginx
    setup_ssl
    start_services
    perform_install_manager_script
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

# Execute installation
perform_install
echo "Installation completed successfully!"
