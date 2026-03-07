#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  InsightLog Installer
# ═══════════════════════════════════════════════════════════════
set -e

echo "╔══════════════════════════════════════╗"
echo "║   InsightLog Installer               ║"
echo "╚══════════════════════════════════════╝"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run as root (sudo ./install.sh)"
    exit 1
fi

# ── System dependencies ───────────────────────────────────────
echo "[+] Installing system dependencies..."
apt-get install -y python3-tk zenity dbus-x11 --quiet

# ── Python package ────────────────────────────────────────────
echo "[+] Installing InsightLog Python package..."
pip3 install -e . --quiet --break-system-packages 2>/dev/null || \
    pip3 install -e . --quiet

# ── Log file permissions ──────────────────────────────────────
chmod a+r /var/log/syslog   2>/dev/null || true
chmod a+r /var/log/auth.log 2>/dev/null || true

# ── CLI wrapper ───────────────────────────────────────────────
cat > /usr/local/bin/insightlog << 'WRAPPER'
#!/usr/bin/env bash
exec python3 -m insightlog.cli "$@"
WRAPPER
chmod +x /usr/local/bin/insightlog

# ── GUI wrapper (auto-elevates to root for full access) ───────
cat > /usr/local/bin/insightlog-gui << 'WRAPPER'
#!/usr/bin/env bash
if [ "$EUID" -ne 0 ]; then
    exec sudo /usr/local/bin/insightlog-gui "$@"
fi
exec python3 -m insightlog.gui "$@"
WRAPPER
chmod +x /usr/local/bin/insightlog-gui

# ── Sudoers: passwordless insightlog-gui ──────────────────────
echo "[+] Adding passwordless sudo for insightlog-gui..."
echo "${REAL_USER} ALL=(ALL) NOPASSWD: /usr/local/bin/insightlog-gui" \
    > /etc/sudoers.d/insightlog
chmod 440 /etc/sudoers.d/insightlog
echo "    Written: /etc/sudoers.d/insightlog" 

# ── Desktop launcher ──────────────────────────────────────────
cat > /usr/share/applications/insightlog.desktop << 'EOF'
[Desktop Entry]
Name=InsightLog
Comment=Linux Security Monitoring Dashboard
Exec=insightlog-gui
Icon=security-high
Terminal=false
Type=Application
Categories=System;Security;
EOF

# ── Systemd service (Type=simple, no double-fork) ─────────────
echo "[+] Writing systemd service..."

PYTHON_BIN=$(which python3)
INSIGHTLOG_DIR=$(pwd)

# Detect the logged-in user's display environment
# SUDO_USER is the user who ran sudo — their session has the display
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo '')}"
REAL_UID=$(id -u "$REAL_USER" 2>/dev/null || echo "1000")
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

# Get DISPLAY directly from the user's live session environment
DETECTED_DISPLAY=$(su - "$REAL_USER" -c 'echo $DISPLAY' 2>/dev/null | tr -d '[:space:]')
[ -z "$DETECTED_DISPLAY" ] && DETECTED_DISPLAY=$(who | grep -oP '\(:\d+\)' | head -1 | tr -d '()' 2>/dev/null)
[ -z "$DETECTED_DISPLAY" ] && DETECTED_DISPLAY=":0"

XAUTHORITY_PATH="${REAL_HOME}/.Xauthority"
DBUS_PATH="unix:path=/run/user/${REAL_UID}/bus"

echo "    User       : $REAL_USER (UID $REAL_UID)"

# ── Directories (now that we know REAL_USER) ──────────────────
mkdir -p /var/lib/insightlog
mkdir -p /var/log
# Group-writable so both root (daemon) and the install user (CLI) share one DB
chown root:"$REAL_USER" /var/lib/insightlog 2>/dev/null || true
chmod 775 /var/lib/insightlog
chmod 664 /var/lib/insightlog/*.db 2>/dev/null || true
echo "    Display    : $DETECTED_DISPLAY"
echo "    Xauthority : $XAUTHORITY_PATH"
echo "    DBus       : $DBUS_PATH"

# Allow root to show GUI popups on the user's display
echo "[+] Granting root access to display $DETECTED_DISPLAY..."
su - "$REAL_USER" -c "xhost +local:root" 2>/dev/null || true

# Persist xhost grant so it survives reboots
BASHRC="${REAL_HOME}/.bashrc"
if ! grep -q "xhost +local:root" "$BASHRC" 2>/dev/null; then
    echo "" >> "$BASHRC"
    echo "# InsightLog — allow daemon alerts on this display" >> "$BASHRC"
    echo "xhost +local:root &>/dev/null" >> "$BASHRC"
    echo "    Persisted xhost grant in $BASHRC"
fi

cat > /etc/systemd/system/insightlog.service << EOF
[Unit]
Description=InsightLog Security Monitor
After=network.target syslog.target
Wants=network.target

[Service]
Type=simple
ExecStart=${PYTHON_BIN} -m insightlog.daemon_simple
WorkingDirectory=${INSIGHTLOG_DIR}
Restart=always
RestartSec=5
StandardOutput=append:/var/log/insightlog_daemon.log
StandardError=append:/var/log/insightlog_daemon.log
Environment=PYTHONPATH=${INSIGHTLOG_DIR}
Environment=PYTHONUNBUFFERED=1
Environment=DISPLAY=${DETECTED_DISPLAY}
Environment=XAUTHORITY=${XAUTHORITY_PATH}
Environment=DBUS_SESSION_BUS_ADDRESS=${DBUS_PATH}

[Install]
WantedBy=multi-user.target
EOF

# ── Enable and start ──────────────────────────────────────────
echo "[+] Enabling and starting service..."
systemctl daemon-reload
systemctl enable insightlog
systemctl restart insightlog

sleep 2
systemctl status insightlog --no-pager

echo ""
echo "✓ InsightLog installed and running!"
echo ""
echo "Commands:"
echo "  sudo systemctl status insightlog              — service status"
echo "  sudo tail -f /var/log/insightlog_daemon.log   — live daemon log"
echo "  insightlog incidents                          — view incidents"
echo "  insightlog-gui                                — open dashboard"
echo ""