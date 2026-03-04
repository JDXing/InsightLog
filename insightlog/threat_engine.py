"""
Rule-based AI Threat Detection Engine
Uses sliding-time-window counting + severity scoring
"""
import json
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional, Dict, Tuple
import db_manager as db

# ─── Threat Rules ────────────────────────────────────────────────────────────
RULES = [
    {
        "id":          "BRUTE_SSH",
        "name":        "SSH Brute Force",
        "event_type":  "ssh_failed",
        "threshold":   5,          # occurrences
        "window_sec":  60,         # in N seconds
        "severity":    "critical",
        "description": "Multiple SSH failed logins detected — possible brute force attack.",
    },
    {
        "id":          "INVALID_USER",
        "name":        "SSH Invalid User Scan",
        "event_type":  "invalid_user",
        "threshold":   3,
        "window_sec":  30,
        "severity":    "high",
        "description": "Multiple SSH attempts with invalid usernames.",
    },
    {
        "id":          "ROOT_LOGIN",
        "name":        "Root Login",
        "event_type":  "root_login",
        "threshold":   1,
        "window_sec":  1,
        "severity":    "high",
        "description": "Direct root session opened.",
    },
    {
        "id":          "SU_FAILED",
        "name":        "Privilege Escalation Failed",
        "event_type":  "su_failed",
        "threshold":   2,
        "window_sec":  60,
        "severity":    "medium",
        "description": "Multiple failed privilege escalation attempts.",
    },
    {
        "id":          "NEW_USER",
        "name":        "Unexpected New User Created",
        "event_type":  "new_user",
        "threshold":   1,
        "window_sec":  1,
        "severity":    "high",
        "description": "A new system user account was created.",
    },
    {
        "id":          "PASSWD_CHANGE",
        "name":        "Password Change",
        "event_type":  "passwd_change",
        "threshold":   1,
        "window_sec":  1,
        "severity":    "medium",
        "description": "A user password was changed.",
    },
    {
        "id":          "PORT_SCAN",
        "name":        "Port Scan Detected",
        "event_type":  "port_scan",
        "threshold":   1,
        "window_sec":  1,
        "severity":    "high",
        "description": "Port scan activity detected in logs.",
    },
    {
        "id":          "KERNEL_PANIC",
        "name":        "Kernel Panic / OOM",
        "event_type":  "kernel_panic",
        "threshold":   1,
        "window_sec":  1,
        "severity":    "critical",
        "description": "Kernel panic or out-of-memory event detected.",
    },
    {
        "id":          "DISK_ERROR",
        "name":        "Disk / IO Error",
        "event_type":  "disk_error",
        "threshold":   1,
        "window_sec":  1,
        "severity":    "high",
        "description": "Disk I/O error detected — possible hardware failure.",
    },
]

RULE_MAP = {r["event_type"]: r for r in RULES}

# Sliding window counters: {(event_type, key): [(timestamp), ...]}
_windows: Dict[Tuple, list] = defaultdict(list)
_lock = threading.Lock()


def _window_key(log: dict) -> str:
    """Group events by source IP or user for window counting."""
    pd = json.loads(log.get("parsed_data") or "{}")
    return pd.get("ip") or pd.get("user") or log.get("host") or "global"


def evaluate(log: dict, log_id: int, on_threat=None):
    """
    Check a parsed log against all rules using sliding time windows.
    Calls on_threat(incident_dict) if a rule fires.
    """
    try:
        pd = json.loads(log.get("parsed_data") or "{}")
    except Exception:
        pd = {}

    event_type = pd.get("event_type")
    if not event_type or event_type not in RULE_MAP:
        return

    rule = RULE_MAP[event_type]
    key  = (event_type, _window_key(log))
    now  = time.time()
    cutoff = now - rule["window_sec"]

    with _lock:
        _windows[key].append(now)
        _windows[key] = [t for t in _windows[key] if t >= cutoff]
        count = len(_windows[key])

    if count >= rule["threshold"]:
        # Reset window to avoid repeated alerts for same burst
        with _lock:
            _windows[key] = []

        incident = {
            "log_id":        log_id,
            "threat_type":   rule["name"],
            "severity":      rule["severity"],
            "description":   rule["description"],
            "source_ip":     pd.get("ip", ""),
            "affected_user": pd.get("user", ""),
            "raw_log":       log.get("raw_line", ""),
            "status":        "open",
        }
        inc_id = db.insert_incident(incident)
        incident["id"] = inc_id
        print(f"\n[THREAT] {rule['severity'].upper()} — {rule['name']} (incident #{inc_id})")
        if on_threat:
            on_threat(incident)


def suggest_actions(incident: dict) -> list:
    """Return a list of suggested remediation actions for a given threat."""
    t = incident.get("threat_type", "")
    ip   = incident.get("source_ip", "")
    user = incident.get("affected_user", "")

    suggestions = {
        "SSH Brute Force": [
            f"Block IP: iptables -A INPUT -s {ip} -j DROP" if ip else "Block attacking IP with iptables",
            f"Lock user account: passwd -l {user}" if user else "Audit SSH user accounts",
            "Review /etc/ssh/sshd_config — disable password auth",
            "Enable fail2ban for SSH",
        ],
        "SSH Invalid User Scan": [
            f"Block IP: iptables -A INPUT -s {ip} -j DROP" if ip else "Block scanning IP",
            "Enable AllowUsers in sshd_config",
        ],
        "Root Login": [
            "Disable root SSH: set PermitRootLogin no in sshd_config",
            "Review who logged in as root and why",
            "Enforce sudo usage instead of direct root login",
        ],
        "Privilege Escalation Failed": [
            f"Investigate user {user}" if user else "Audit sudoers file",
            "Review /etc/sudoers for unnecessary permissions",
        ],
        "Unexpected New User Created": [
            f"Remove user: userdel -r {user}" if user else "Audit newly created accounts",
            "Check /etc/passwd for unauthorized accounts",
        ],
        "Password Change": [
            f"Verify {user} authorized this change" if user else "Audit recent password changes",
            "Check for unauthorized access before change",
        ],
        "Port Scan Detected": [
            f"Block scanner: iptables -A INPUT -s {ip} -j DROP" if ip else "Identify scan source",
            "Review open ports: ss -tlnp",
            "Enable ufw or nftables rules",
        ],
        "Kernel Panic / OOM": [
            "Check memory: free -h && vmstat",
            "Review /var/log/kern.log for details",
            "Consider reboot if system is unstable",
        ],
        "Disk / IO Error": [
            "Check disk health: smartctl -a /dev/sda",
            "Run fsck on affected partition",
            "Review /var/log/kern.log for disk errors",
        ],
    }
    return suggestions.get(t, ["Investigate logs manually", "Escalate to senior admin"])