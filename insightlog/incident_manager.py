"""
Incident Manager
Manages incident lifecycle, sends terminal alerts, triggers Decision Support
"""
import os
import subprocess
import threading
from datetime import datetime
from typing import Callable, Optional
import db_manager as db
from threat_engine import suggest_actions

ALERT_LOG = "/var/log/insightlog_alerts.log"
_alert_callbacks = []   # Registered alert handlers


def register_alert_handler(fn: Callable):
    _alert_callbacks.append(fn)


def handle_new_incident(incident: dict):
    """Called by threat engine when a new incident is created."""
    inc_id   = incident["id"]
    severity = incident["severity"].upper()
    threat   = incident["threat_type"]
    desc     = incident["description"]
    ip       = incident.get("source_ip", "")
    user     = incident.get("affected_user", "")

    msg_lines = [
        f"\n{'='*60}",
        f" ⚠  INSIGHTLOG ALERT — Incident #{inc_id}",
        f"{'='*60}",
        f"  Severity : {severity}",
        f"  Threat   : {threat}",
        f"  Details  : {desc}",
    ]
    if ip:   msg_lines.append(f"  Source IP: {ip}")
    if user: msg_lines.append(f"  User     : {user}")
    msg_lines += [
        f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"",
        f"  Run:  insightlog respond --incident {inc_id}",
        f"  Or :  insightlog chat --incident {inc_id}",
        f"{'='*60}\n",
    ]
    alert_msg = "\n".join(msg_lines)

    # Write to alert log
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(alert_msg)
    except Exception:
        pass

    # Print to all terminals (wall message)
    try:
        subprocess.run(["wall", alert_msg], capture_output=True, timeout=3)
    except Exception:
        pass

    # Fire registered callbacks
    for cb in _alert_callbacks:
        try: cb(incident)
        except Exception: pass

    # Desktop notification (if available)
    try:
        subprocess.run(
            ["notify-send", f"InsightLog [{severity}]", f"{threat}\nIncident #{inc_id}"],
            capture_output=True, timeout=2
        )
    except Exception:
        pass


def list_incidents(status: str = "open", limit: int = 20) -> list:
    return db.query_incidents({"status": status}, limit=limit)


def resolve_incident(inc_id: int, notes: str = ""):
    db.update_incident(inc_id, "resolved", notes)
    db.insert_audit({
        "incident_id": inc_id,
        "action_type": "resolve",
        "command":     "manual_resolve",
        "result":      notes or "Resolved by operator",
        "approved_by": "operator",
        "success":     1,
    })
    print(f"[IncidentManager] Incident #{inc_id} marked as resolved.")


def get_suggestions(inc_id: int) -> list:
    inc = db.get_incident(inc_id)
    if not inc:
        return ["Incident not found."]
    return suggest_actions(inc)