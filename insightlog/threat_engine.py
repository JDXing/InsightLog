"""
InsightLog - Rule-Based Threat Detection Engine
Sliding time window + severity scoring
"""
import json
import time
import threading
from typing import Dict, Tuple
from collections import defaultdict

from insightlog import db_manager as db

RULES = [
    {
        "id":          "BRUTE_SSH",
        "name":        "SSH Brute Force",
        "event_type":  "ssh_failed",
        "threshold":   5,
        "window_sec":  60,
        "severity":    "critical",
        "description": "Multiple SSH failed logins — possible brute force attack.",
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
_windows: Dict[Tuple, list] = defaultdict(list)
_lock = threading.Lock()


def _window_key(log: dict) -> str:
    try:
        pd = json.loads(log.get("parsed_data") or "{}")
    except Exception:
        pd = {}
    return pd.get("ip") or pd.get("user") or log.get("host") or "global"


def evaluate(log: dict, log_id: int, on_threat=None):
    try:
        pd = json.loads(log.get("parsed_data") or "{}")
    except Exception:
        pd = {}

    event_type = pd.get("event_type")
    if not event_type or event_type not in RULE_MAP:
        return

    rule   = RULE_MAP[event_type]
    key    = (event_type, _window_key(log))
    now    = time.time()
    cutoff = now - rule["window_sec"]

    with _lock:
        _windows[key].append(now)
        _windows[key] = [t for t in _windows[key] if t >= cutoff]
        count = len(_windows[key])

    if count >= rule["threshold"]:
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
        print(f"\n[THREAT] {rule['severity'].upper()} — "
              f"{rule['name']} (incident #{inc_id})")
        if on_threat:
            on_threat(incident)


def suggest_actions(incident: dict) -> list:
    t    = incident.get("threat_type", "")
    ip   = incident.get("source_ip", "")
    user = incident.get("affected_user", "")

    suggestions = {
        "SSH Brute Force": [
            f"Block IP: iptables -A INPUT -s {ip} -j DROP"
                if ip else "Block attacking IP with iptables",
            f"Lock user: passwd -l {user}" if user else "Audit SSH accounts",
            "Disable password auth in /etc/ssh/sshd_config",
            "Enable fail2ban: systemctl enable --now fail2ban",
        ],
        "SSH Invalid User Scan": [
            f"Block IP: iptables -A INPUT -s {ip} -j DROP"
                if ip else "Block scanning IP",
            "Restrict SSH with AllowUsers in sshd_config",
        ],
        "Root Login": [
            "Disable root SSH: set PermitRootLogin no in sshd_config",
            "Enforce sudo usage instead of direct root login",
            "Review root login source immediately",
        ],
        "Privilege Escalation Failed": [
            f"Investigate user {user}" if user else "Audit sudoers",
            "Review /etc/sudoers for unnecessary permissions",
        ],
        "Unexpected New User Created": [
            f"Remove user: userdel -r {user}" if user else "Audit new accounts",
            "Check /etc/passwd for unauthorized accounts",
        ],
        "Password Change": [
            f"Verify {user} authorized this change"
                if user else "Audit recent password changes",
            "Check for unauthorized access before change",
        ],
        "Port Scan Detected": [
            f"Block scanner: iptables -A INPUT -s {ip} -j DROP"
                if ip else "Identify scan source",
            "Review open ports: ss -tlnp",
            "Harden firewall rules with ufw",
        ],
        "Kernel Panic / OOM": [
            "Check memory usage: free -h",
            "Review kernel log: journalctl -k --since today",
            "Consider system reboot if unstable",
        ],
        "Disk / IO Error": [
            "Check disk health: smartctl -a /dev/sda",
            "Run filesystem check: fsck /dev/sda1",
            "Review kernel log for disk errors",
        ],
    }
    return suggestions.get(t, [
        "Investigate logs manually",
        "Escalate to senior administrator",
    ])