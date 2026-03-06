"""
InsightLog - Incident Manager
Alerts always fire from the daemon (independent of GUI).
Clicking 'Open Dashboard' launches the GUI pre-loaded with the incident.
Uses tkinter for popup (works on Wayland/VM).
"""
import os
import subprocess
import threading
import tempfile
from datetime import datetime
from typing import Callable

from insightlog import db_manager as db
from insightlog.threat_engine import suggest_actions

ALERT_LOG = "/var/log/insightlog_alerts.log"
GUI_CMD   = "/usr/local/bin/insightlog-gui"
_alert_callbacks = []


def register_alert_handler(fn: Callable):
    _alert_callbacks.append(fn)


# ── Display environment ───────────────────────────────────────────────────────

def _get_display_env() -> dict:
    env = os.environ.copy()

    if not env.get("DISPLAY"):
        env["DISPLAY"] = ":0"

    try:
        import glob
        for pattern in ["/home/*/.Xauthority", "/run/user/*/.Xauthority"]:
            matches = glob.glob(pattern)
            if matches:
                env.setdefault("XAUTHORITY", matches[0])
                break
    except Exception:
        pass

    try:
        import glob
        buses = glob.glob("/run/user/*/bus")
        if buses:
            env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={buses[0]}")
    except Exception:
        pass

    try:
        import glob
        sockets = glob.glob("/run/user/*/wayland-*")
        if sockets:
            env["WAYLAND_DISPLAY"] = os.path.basename(sockets[0])
            uid = sockets[0].split("/")[3]
            env["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"
    except Exception:
        pass

    return env


# ── GUI launch ────────────────────────────────────────────────────────────────

def _open_gui(inc_id: int, env: dict):
    for cmd in [
        [GUI_CMD, "--incident", str(inc_id)],
        ["/opt/insightlog/venv/bin/insightlog-gui", "--incident", str(inc_id)],
        ["python3", "-m", "insightlog.gui", "--incident", str(inc_id)],
    ]:
        try:
            subprocess.Popen(
                cmd, env=env,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except Exception:
            continue


# ── Tkinter popup ─────────────────────────────────────────────────────────────

def _show_tkinter_popup(inc_id: int, threat: str, severity: str,
                         popup_msg: str, env: dict):
    """
    Write the popup as a standalone Python script to a temp file
    and run it in a subprocess — avoids all f-string/quote conflicts.
    """
    sev_colors = {
        "critical": "#ff3355",
        "high":     "#ff8800",
        "medium":   "#ffcc00",
        "low":      "#00ff88",
    }
    color = sev_colors.get(severity.lower(), "#ff8800")

    # Escape single quotes in dynamic strings for safe embedding
    safe_threat    = threat.replace("'", "\\'")
    safe_msg       = popup_msg.replace("'", "\\'").replace("\n", "\\n")
    safe_sev       = severity.upper().replace("'", "\\'")
    safe_gui_cmd   = GUI_CMD.replace("'", "\\'")

    script = (
        "import tkinter as tk\n"
        "import subprocess, os\n"
        "\n"
        "inc_id   = " + str(inc_id) + "\n"
        "color    = '" + color + "'\n"
        "threat   = '" + safe_threat + "'\n"
        "severity = '" + safe_sev + "'\n"
        "msg_raw  = '" + safe_msg + "'\n"
        "msg      = msg_raw.replace('\\\\n', '\\n')\n"
        "gui_cmd  = '" + safe_gui_cmd + "'\n"
        "\n"
        "root = tk.Tk()\n"
        "root.title('InsightLog — Security Alert')\n"
        "root.configure(bg='#0a0e1a')\n"
        "root.resizable(False, False)\n"
        "root.attributes('-topmost', True)\n"
        "root.lift()\n"
        "root.focus_force()\n"
        "\n"
        "hdr = tk.Frame(root, bg=color, pady=10)\n"
        "hdr.pack(fill='x')\n"
        "tk.Label(hdr,\n"
        "    text='  INSIGHTLOG ALERT  Incident #' + str(inc_id),\n"
        "    bg=color, fg='#0a0e1a',\n"
        "    font=('Courier New', 12, 'bold')\n"
        ").pack(side='left', padx=12)\n"
        "tk.Label(hdr, text=' ' + severity + ' ',\n"
        "    bg='#0a0e1a', fg=color,\n"
        "    font=('Courier New', 10, 'bold'), padx=6\n"
        ").pack(side='right', padx=12)\n"
        "\n"
        "body = tk.Frame(root, bg='#0a0e1a', padx=24, pady=16)\n"
        "body.pack(fill='both', expand=True)\n"
        "tk.Label(body, text=msg,\n"
        "    bg='#0a0e1a', fg='#c8d4e8',\n"
        "    font=('Courier New', 10),\n"
        "    justify='left', anchor='w'\n"
        ").pack(anchor='w')\n"
        "\n"
        "countdown_var = tk.StringVar(value='Auto-closing in 60s')\n"
        "tk.Label(body, textvariable=countdown_var,\n"
        "    bg='#0a0e1a', fg='#6b7fa3',\n"
        "    font=('Courier New', 8)\n"
        ").pack(anchor='e', pady=(8, 0))\n"
        "remaining = [60]\n"
        "def tick():\n"
        "    remaining[0] -= 1\n"
        "    countdown_var.set('Auto-closing in ' + str(remaining[0]) + 's')\n"
        "    if remaining[0] <= 0:\n"
        "        root.destroy()\n"
        "    else:\n"
        "        root.after(1000, tick)\n"
        "root.after(1000, tick)\n"
        "\n"
        "btn_row = tk.Frame(root, bg='#0a0e1a', padx=24, pady=12)\n"
        "btn_row.pack(fill='x')\n"
        "def open_dashboard():\n"
        "    root.destroy()\n"
        "    env = os.environ.copy()\n"
        "    for cmd in [\n"
        "        [gui_cmd, '--incident', str(inc_id)],\n"
        "        ['/opt/insightlog/venv/bin/insightlog-gui', '--incident', str(inc_id)],\n"
        "        ['python3', '-m', 'insightlog.gui', '--incident', str(inc_id)],\n"
        "    ]:\n"
        "        try:\n"
        "            subprocess.Popen(cmd, env=env, start_new_session=True,\n"
        "                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "            break\n"
        "        except Exception:\n"
        "            continue\n"
        "tk.Button(btn_row, text='  Open Dashboard  ',\n"
        "    command=open_dashboard,\n"
        "    bg=color, fg='#0a0e1a',\n"
        "    font=('Courier New', 10, 'bold'),\n"
        "    relief='flat', padx=12, pady=8, cursor='hand2'\n"
        ").pack(side='left', padx=(0, 10))\n"
        "tk.Button(btn_row, text='  Dismiss  ',\n"
        "    command=root.destroy,\n"
        "    bg='#1e2d4a', fg='#c8d4e8',\n"
        "    font=('Courier New', 10),\n"
        "    relief='flat', padx=12, pady=8, cursor='hand2'\n"
        ").pack(side='left')\n"
        "root.mainloop()\n"
    )

    def _run():
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False
            ) as f:
                f.write(script)
                tmp = f.name
            subprocess.run(
                ["python3", tmp],
                env=env,
                timeout=70,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except Exception:
                    pass

    threading.Thread(target=_run, daemon=True, name=f"alert-{inc_id}").start()


# ── Wall + log ────────────────────────────────────────────────────────────────

def _send_wall(alert_msg: str):
    try:
        subprocess.run(["wall", alert_msg], capture_output=True, timeout=3)
    except Exception:
        pass


def _write_alert_log(alert_msg: str):
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(alert_msg + "\n")
    except Exception:
        pass


# ── Main handler ──────────────────────────────────────────────────────────────

def handle_new_incident(incident: dict):
    inc_id   = incident["id"]
    severity = incident["severity"]
    threat   = incident["threat_type"]
    desc     = incident["description"]
    ip       = incident.get("source_ip",     "")
    user     = incident.get("affected_user", "")
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Terminal / log message
    lines = [
        f"\n{'='*58}",
        f" INSIGHTLOG ALERT - Incident #{inc_id}",
        f"{'='*58}",
        f"  Severity  : {severity.upper()}",
        f"  Threat    : {threat}",
        f"  Details   : {desc}",
    ]
    if ip:   lines.append(f"  Source IP : {ip}")
    if user: lines.append(f"  User      : {user}")
    lines += [
        f"  Time      : {ts}",
        f"{'='*58}",
        f"",
        f"  GUI : insightlog-gui --incident {inc_id}",
        f"  CLI : insightlog respond --incident {inc_id}",
        f"{'='*58}",
    ]
    alert_msg = "\n".join(lines)

    # Popup message
    popup_parts = [
        f"Threat    : {threat}",
        f"Severity  : {severity.upper()}",
        f"Details   : {desc}",
    ]
    if ip:   popup_parts.append(f"Source IP : {ip}")
    if user: popup_parts.append(f"User      : {user}")
    popup_parts += [f"Time      : {ts}", "", "Click 'Open Dashboard' to respond."]
    popup_msg = "\n".join(popup_parts)

    env = _get_display_env()

    # 1. Tkinter popup
    _show_tkinter_popup(inc_id, threat, severity, popup_msg, env)

    # 2. Wall broadcast
    _send_wall(alert_msg)

    # 3. Alert log
    _write_alert_log(alert_msg)

    # 4. Callbacks
    for cb in _alert_callbacks:
        try:
            cb(incident)
        except Exception:
            pass

    print(f"[Alert] Incident #{inc_id} - {severity.upper()} - {threat}", flush=True)


# ── Utilities ─────────────────────────────────────────────────────────────────

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