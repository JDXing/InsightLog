#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  InsightLog Installer
# ═══════════════════════════════════════════════════════════════
set -e

echo "╔══════════════════════════════════════╗"
echo "║   InsightLog Installer               ║"
echo "╚══════════════════════════════════════╝"

# ── Self-heal: remove any broken sudoers file BEFORE sudo is needed ─────────
rm -f /etc/sudoers.d/insightlog 2>/dev/null || true

# ── Must run as root ──────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run as root (sudo ./install.sh)"
    exit 1
fi

# ── Detect paths immediately — everything depends on these ────
INSIGHTLOG_DIR=$(realpath "$(dirname "$0")")
PYTHON_BIN=$(which python3)

# Detect the real user who ran sudo (not root)
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo '')}"
if [ -z "$REAL_USER" ] || [ "$REAL_USER" = "root" ]; then
    REAL_USER=$(getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1; exit}')
fi
REAL_UID=$(id -u "$REAL_USER" 2>/dev/null || echo "1000")
REAL_HOME=$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6 || echo "/home/$REAL_USER")

echo "    Install dir : $INSIGHTLOG_DIR"
echo "    Python      : $PYTHON_BIN"
echo "    User        : $REAL_USER (UID $REAL_UID)"
echo "    Home        : $REAL_HOME"

# ── System dependencies ───────────────────────────────────────
echo ""
echo "[+] Installing system dependencies..."
apt-get install -y python3-tk --quiet

# ── Ensure syslog exists (Kali/journald systems) ─────────────
echo "[+] Checking syslog availability..."
if [ ! -f /var/log/syslog ] && [ ! -f /var/log/messages ]; then
    echo "    syslog not found — installing rsyslog..."
    apt-get install -y -q rsyslog
    systemctl enable rsyslog
    systemctl start rsyslog
    sleep 2
    echo "    rsyslog installed and started."
else
    echo "    syslog found."
fi

# ── Directories ───────────────────────────────────────────────
echo "[+] Setting up directories..."
mkdir -p /var/lib/insightlog
mkdir -p /var/log
chmod 755 /var/lib/insightlog
if [ -n "$REAL_USER" ]; then
    chown root:"$REAL_USER" /var/lib/insightlog 2>/dev/null || true
    chmod 775 /var/lib/insightlog
fi
chmod 664 /var/lib/insightlog/*.db 2>/dev/null || true

# ── Log file permissions ──────────────────────────────────────
chmod a+r /var/log/syslog    2>/dev/null || true
chmod a+r /var/log/auth.log  2>/dev/null || true
chmod a+r /var/log/messages  2>/dev/null || true
chmod a+r /var/log/kern.log  2>/dev/null || true
chmod a+r /var/log/secure    2>/dev/null || true

# ── Install Python package ────────────────────────────────────
echo "[+] Installing InsightLog Python package..."
pip3 install -e "$INSIGHTLOG_DIR" --quiet --break-system-packages 2>/dev/null \
    || pip3 install -e "$INSIGHTLOG_DIR" --quiet \
    || python3 -m pip install -e "$INSIGHTLOG_DIR" --quiet --break-system-packages 2>/dev/null \
    || python3 -m pip install -e "$INSIGHTLOG_DIR" --quiet

# ── CLI wrapper ───────────────────────────────────────────────
echo "[+] Writing CLI wrapper..."
cat > /usr/local/bin/insightlog << WRAPPER
#!/usr/bin/env bash
export PYTHONPATH="${INSIGHTLOG_DIR}:\${PYTHONPATH}"
exec python3 -m insightlog.cli "\$@"
WRAPPER
chmod +x /usr/local/bin/insightlog

# ── GUI wrapper (auto-elevates to root for full access) ───────
echo "[+] Writing GUI wrapper..."
cat > /usr/local/bin/insightlog-gui << WRAPPER
#!/usr/bin/env bash
export PYTHONPATH="${INSIGHTLOG_DIR}:\${PYTHONPATH}"
if [ "\$EUID" -ne 0 ]; then
    exec sudo /usr/local/bin/insightlog-gui "\$@"
fi
exec python3 -m insightlog.gui "\$@"
WRAPPER
chmod +x /usr/local/bin/insightlog-gui

# ── Sudoers: passwordless insightlog-gui ─────────────────────
echo "[+] Configuring sudoers..."
rm -f /etc/sudoers.d/insightlog
if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
    echo "${REAL_USER} ALL=(ALL) NOPASSWD: /usr/local/bin/insightlog-gui" \
        > /etc/sudoers.d/insightlog
    chmod 440 /etc/sudoers.d/insightlog
    if visudo -c -f /etc/sudoers.d/insightlog >/dev/null 2>&1; then
        echo "    Written: /etc/sudoers.d/insightlog (for user $REAL_USER)"
    else
        echo "    WARNING: sudoers validation failed — removing to avoid blocking sudo."
        rm -f /etc/sudoers.d/insightlog
    fi
else
    echo "    WARNING: Could not detect non-root user — skipping sudoers entry."
fi

# ── Desktop launcher ──────────────────────────────────────────
echo "[+] Writing desktop launcher..."
cat > /usr/share/applications/insightlog.desktop << 'DESKTOP'
[Desktop Entry]
Name=InsightLog
Comment=Linux Security Monitoring Dashboard
Exec=insightlog-gui
Icon=security-high
Terminal=false
Type=Application
Categories=System;Security;
DESKTOP

# ── Detect display environment ────────────────────────────────
echo "[+] Detecting display environment..."
DETECTED_DISPLAY=$(su - "$REAL_USER" -c 'echo $DISPLAY' 2>/dev/null | tr -d '[:space:]')
[ -z "$DETECTED_DISPLAY" ] && \
    DETECTED_DISPLAY=$(who | grep -oP '\(:\d+\)' | head -1 | tr -d '()' 2>/dev/null)
[ -z "$DETECTED_DISPLAY" ] && DETECTED_DISPLAY=":0"

XAUTHORITY_PATH="${REAL_HOME}/.Xauthority"
DBUS_PATH="unix:path=/run/user/${REAL_UID}/bus"

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

# ── Systemd service ───────────────────────────────────────────
echo "[+] Writing systemd service..."
cat > /etc/systemd/system/insightlog.service << SERVICE
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
SERVICE

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