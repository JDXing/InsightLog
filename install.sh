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

echo "[1/6] Creating install directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p /var/lib/insightlog
mkdir -p /var/log
chmod 750 /var/lib/insightlog

echo "[2/6] Creating virtual environment..."
python3 -m venv "$VENV_DIR"

echo "[3/6] Installing package into venv..."
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -e "$SRC_DIR"

echo "[4/6] Setting log file permissions..."
chmod +r /var/log/syslog   2>/dev/null || true
chmod +r /var/log/auth.log 2>/dev/null || true

echo "[5/6] Creating systemd service..."
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

echo "[6/6] Enabling and starting service..."
systemctl daemon-reload
systemctl enable insightlog
systemctl start insightlog

# Create a global wrapper so 'insightlog' works from anywhere
cat > /usr/local/bin/insightlog << EOF
#!/usr/bin/env bash
exec $VENV_DIR/bin/insightlog "\$@"
EOF
chmod +x /usr/local/bin/insightlog

echo ""
echo "✓ InsightLog installed successfully!"
echo ""
echo "  Service  : $(systemctl is-active insightlog)"
echo "  Venv     : $VENV_DIR"
echo "  Databases: /var/lib/insightlog/"
echo "  Logs     : /var/log/insightlog_daemon.log"
echo "  Alerts   : /var/log/insightlog_alerts.log"
echo ""
echo "Quick reference:"
echo "  insightlog status                    — daemon status"
echo "  insightlog incidents                 — view open incidents"
echo "  insightlog chat                      — Decision Support Interface"
echo "  insightlog postmortem                — 7-day threat analysis"
echo "  insightlog logs --search 'Failed'    — search logs"
echo "  insightlog respond --incident <id>   — respond to threat"
echo ""