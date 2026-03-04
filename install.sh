#!/usr/bin/env bash
set -e

echo "╔══════════════════════════════════════╗"
echo "║   InsightLog Installer               ║"
echo "╚══════════════════════════════════════╝"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run as root (sudo ./install.sh)"
    exit 1
fi

# Create directories
mkdir -p /var/lib/insightlog
mkdir -p /var/log
chmod 750 /var/lib/insightlog

# Install Python package
pip3 install -e . --quiet

# Grant log access
chmod +r /var/log/syslog   2>/dev/null || true
chmod +r /var/log/auth.log 2>/dev/null || true

# Systemd service
cat > /etc/systemd/system/insightlog.service << 'EOF'
[Unit]
Description=InsightLog Security Monitor
After=network.target
DefaultDependencies=false

[Service]
Type=forking
ExecStart=/usr/local/bin/insightlog start
ExecStop=/usr/local/bin/insightlog stop
PIDFile=/var/run/insightlog.pid
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable insightlog
systemctl start insightlog

echo ""
echo "✓ InsightLog installed and running!"
echo ""
echo "Quick reference:"
echo "  insightlog status          — daemon status"
echo "  insightlog incidents       — view open incidents"
echo "  insightlog chat            — open Decision Support Interface"
echo "  insightlog postmortem      — 7-day threat analysis"
echo "  insightlog logs --search X — search logs"
echo "  insightlog respond --incident <id>  — respond to threat"
echo ""
```

---

## How Everything Flows (matches your DFD)
```
Linux syslog/auth.log
        │ Logs
        ▼
  [LogTailer] (log_ingestor.py)
        │ parse_line() — regex → structured dict
        ▼
   [D1: d1_logs.db]
        │
        ▼
  [ThreatEngine] (threat_engine.py)
    sliding-window rule evaluation
        │ threat detected
        ▼
   [D2: d2_incidents.db]
        │
        ▼
  [IncidentManager] (incident_manager.py)
    wall alert + notify-send + alert log
        │ Alert
        ▼
  [Security Operator terminal]
        │
        ▼
  [DecisionSupport] (decision_support.py)
    queries D1 + D2, suggests actions
        │ Human approves
        ▼
  [ResponseExecutor] (response_executor.py)
    executes safe commands
        │
        ▼
   [D3: d3_audit.db]