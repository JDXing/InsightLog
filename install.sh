#!/usr/bin/env bash
set -e

echo "╔══════════════════════════════════════╗"
echo "║   InsightLog Installer               ║"
echo "╚══════════════════════════════════════╝"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run as root (sudo ./install.sh)"
    exit 1
fi

INSTALL_DIR="/opt/insightlog"
VENV_DIR="$INSTALL_DIR/venv"
SRC_DIR="$(pwd)"

echo "[1/7] Creating install directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p /var/lib/insightlog
mkdir -p /var/log
chmod 750 /var/lib/insightlog

echo "[2/7] Installing system dependencies..."
apt install -y python3-tk python3-venv python3-pip 2>/dev/null || true

echo "[3/7] Creating virtual environment..."
python3 -m venv "$VENV_DIR"

echo "[4/7] Installing package into venv..."
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet setuptools
"$VENV_DIR/bin/pip" install --quiet -e "$SRC_DIR"

echo "[5/7] Setting log file permissions..."
chmod +r /var/log/syslog   2>/dev/null || true
chmod +r /var/log/auth.log 2>/dev/null || true

echo "[6/7] Creating systemd service..."
cat > /etc/systemd/system/insightlog.service << EOF
[Unit]
Description=InsightLog Security Monitor
After=network.target syslog.target

[Service]
Type=forking
ExecStart=$VENV_DIR/bin/insightlog start
ExecStop=$VENV_DIR/bin/insightlog stop
PIDFile=/var/run/insightlog.pid
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "[7/7] Creating global commands..."

# CLI command
cat > /usr/local/bin/insightlog << EOF
#!/usr/bin/env bash
exec $VENV_DIR/bin/insightlog "\$@"
EOF
chmod +x /usr/local/bin/insightlog

# GUI command
cat > /usr/local/bin/insightlog-gui << EOF
#!/usr/bin/env bash
exec $VENV_DIR/bin/insightlog-gui "\$@"
EOF
chmod +x /usr/local/bin/insightlog-gui

# Desktop launcher
cat > /usr/share/applications/insightlog.desktop << EOF
[Desktop Entry]
Name=InsightLog
Comment=Linux Security Monitoring Dashboard
Exec=/usr/local/bin/insightlog-gui
Icon=security-high
Terminal=false
Type=Application
Categories=System;Security;Monitor;
StartupNotify=true
EOF

# Enable and start daemon
systemctl daemon-reload
systemctl enable insightlog
systemctl start insightlog

echo ""
echo "✓ InsightLog installed successfully!"
echo ""
echo "  Daemon  : $(systemctl is-active insightlog)"
echo "  Venv    : $VENV_DIR"
echo "  DBs     : /var/lib/insightlog/"
echo ""
echo "  CLI : insightlog <command>"
echo "  GUI : insightlog-gui"
echo ""