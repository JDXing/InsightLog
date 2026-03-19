"""
InsightLog - Rule-Based Threat Detection Engine
Sliding time window + severity scoring
"""
import json
import time
import threading
from typing import Dict, Tuple
from collections import defaultdict

import os
import pwd
from insightlog import db_manager as db

def _get_protected_users() -> set:
    """
    Returns usernames that must never be locked, deleted, or modified.
    Includes: current operator, root, and any user in the sudo/wheel group.
    """
    protected = {"root"}
    # whoever is running the daemon / GUI
    try:
        protected.add(os.environ.get("SUDO_USER", ""))
        protected.add(pwd.getpwuid(os.getuid()).pw_name)
        protected.add(pwd.getpwuid(os.geteuid()).pw_name)
    except Exception:
        pass
    # all members of sudo and wheel groups
    try:
        import grp
        for grp_name in ("sudo", "wheel", "admin"):
            try:
                protected.update(grp.getgrnam(grp_name).gr_mem)
            except KeyError:
                pass
    except Exception:
        pass
    return {u for u in protected if u}  # drop empty strings

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


def _parse_pd(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return {}
    return {}


def _window_key(log: dict, pd: dict) -> str:
    return pd.get("ip") or pd.get("user") or log.get("host") or "global"


def evaluate(log: dict, log_id: int, on_threat=None):
    pd = _parse_pd(log.get("parsed_data"))
    event_type = pd.get("event_type")
    if not event_type or event_type not in RULE_MAP:
        return

    rule   = RULE_MAP[event_type]
    key    = (event_type, _window_key(log, pd))
    now    = time.time()
    cutoff = now - rule["window_sec"]

    with _lock:
        _windows[key].append(now)
        _windows[key] = [t for t in _windows[key] if t >= cutoff]
        count = len(_windows[key])

    print(f"[ThreatEngine] {event_type} count={count}/{rule['threshold']} key={key[1]}", flush=True)

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
        print(f"\n[THREAT] {rule['severity'].upper()} — {rule['name']} (incident #{inc_id})", flush=True)
        if on_threat:
            on_threat(incident)


def suggest_actions(incident: dict) -> list:
    """
    Return suggested actions for an incident.
    Lines starting with '#' are manual/informational — shown greyed out in GUI.
    All other lines are real shell commands that can be executed directly.
    """
    t    = incident.get("threat_type", "")
    ip   = incident.get("source_ip", "")
    user = incident.get("affected_user", "")

    # Safety: never suggest locking or deleting a protected system/operator account
    protected = _get_protected_users()
    if user and user in protected:
        user_lock   = f"# SAFETY: '{user}' is a protected account — do not lock automatically"
        user_delete = f"# SAFETY: '{user}' is a protected account — do not delete automatically"
    else:
        user_lock   = f"passwd -l {user}" if user else "# No user identified — audit accounts manually"
        user_delete = f"userdel -r {user}" if user else "# No user identified — check /etc/passwd manually"

    suggestions = {
        "SSH Brute Force": [
            f"iptables -A INPUT -s {ip} -j DROP"                                         if ip   else "# No source IP — identify attacker manually",
            user_lock if user else "# No user identified — audit SSH accounts",
            "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart ssh",
            "systemctl enable --now fail2ban",
        ],
        "SSH Invalid User Scan": [
            f"iptables -A INPUT -s {ip} -j DROP"                                         if ip   else "# No source IP — identify scanner manually",
            "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart ssh",
            "# Manual: add AllowUsers directive to /etc/ssh/sshd_config",
        ],
        "Root Login": [
            "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart ssh",
            "last | head -20",
            "# Manual: enforce sudo usage — ensure wheel/sudo group is configured",
        ],
        "Privilege Escalation Failed": [
            user_lock if user else "# No user identified — audit sudoers manually",
            "cat /etc/sudoers",
            "last | head -20",
        ],
        "Unexpected New User Created": [
            user_delete if user else "# No user identified — check /etc/passwd manually",
            "cat /etc/passwd | tail -10",
            "last | head -10",
        ],
        "Password Change": [
            user_lock if user else "# No user identified — review recent password changes",
            "last | head -10",
            "# Manual: verify the password change was authorized",
        ],
        "Port Scan Detected": [
            f"iptables -A INPUT -s {ip} -j DROP"                                         if ip   else "# No source IP — identify scanner manually",
            "ss -tlnp",
            "ufw enable",
        ],
        "Kernel Panic / OOM": [
            "free -h",
            "journalctl -k --since today --no-pager | tail -50",
            "# Manual: consider rescheduling services or adding swap if OOM",
        ],
        "Disk / IO Error": [
            "smartctl -a /dev/sda",
            "journalctl -k --since today --no-pager | tail -30",
            "# Manual: back up data immediately if smartctl shows failures",
        ],
    }

    return suggestions.get(t, [
        "# Unknown threat — investigate logs manually",
        "journalctl --since today --no-pager | tail -50",
    ])