#!/usr/bin/env python3
"""
InsightLog GUI — Linux Security Monitoring Dashboard
Dark cybersecurity aesthetic with real-time threat monitoring
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import json
import os
import subprocess
import shlex
from datetime import datetime, timedelta
from collections import defaultdict

# ─── Attempt to import insightlog modules ────────────────────────────────────
try:
    from insightlog import db_manager as db
    from insightlog.threat_engine import suggest_actions, evaluate
    from insightlog.log_ingestor import LogTailer
    from insightlog.incident_manager import handle_new_incident
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

# ─── Color Palette ────────────────────────────────────────────────────────────
C = {
    "bg":        "#0a0e1a",
    "bg2":       "#0f1526",
    "bg3":       "#141c33",
    "panel":     "#111827",
    "border":    "#1e2d4a",
    "accent":    "#00d4ff",
    "accent2":   "#0099cc",
    "green":     "#00ff88",
    "yellow":    "#ffcc00",
    "orange":    "#ff8800",
    "red":       "#ff3355",
    "red2":      "#cc1133",
    "white":     "#e8edf5",
    "gray":      "#4a5568",
    "gray2":     "#2d3748",
    "text":      "#c8d4e8",
    "subtext":   "#6b7fa3",
    "critical":  "#ff3355",
    "high":      "#ff8800",
    "medium":    "#ffcc00",
    "low":       "#00ff88",
}

SEV_COLOR = {
    "critical": C["critical"],
    "high":     C["high"],
    "medium":   C["medium"],
    "low":      C["low"],
}


def fmt_time(ts):
    if not ts:
        return "—"
    try:
        return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def sev_color(sev):
    return SEV_COLOR.get((sev or "").lower(), C["gray"])


# ─── Mock DB ──────────────────────────────────────────────────────────────────
class MockDB:
    _logs      = []
    _incidents = []
    _audit     = []
    _inc_id    = 1
    _log_id    = 1

    @classmethod
    def insert_log(cls, log):
        log["id"] = cls._log_id
        cls._log_id += 1
        cls._logs.append(log)
        return log["id"]

    @classmethod
    def query_logs(cls, filters=None, limit=100):
        results = list(reversed(cls._logs))
        if filters:
            if "log_type" in filters:
                results = [l for l in results if l.get("log_type") == filters["log_type"]]
            if "keyword" in filters:
                results = [l for l in results if filters["keyword"].lower() in (l.get("message","") or "").lower()]
        return results[:limit]

    @classmethod
    def get_log_stats(cls):
        by_type = {}
        for l in cls._logs:
            t = l.get("log_type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        return {"total": len(cls._logs), "by_type": by_type}

    @classmethod
    def insert_incident(cls, inc):
        inc = dict(inc)
        inc["id"]          = cls._inc_id
        inc["detected_at"] = datetime.now().isoformat()
        inc["status"]      = inc.get("status", "open")
        cls._incidents.append(inc)
        cls._inc_id += 1
        return inc["id"]

    @classmethod
    def query_incidents(cls, filters=None, limit=50):
        results = list(reversed(cls._incidents))
        if filters:
            if filters.get("status"):
                results = [i for i in results if i.get("status") == filters["status"]]
            if filters.get("severity"):
                results = [i for i in results if i.get("severity") == filters["severity"]]
        return results[:limit]

    @classmethod
    def get_incident(cls, inc_id):
        for i in cls._incidents:
            if i.get("id") == inc_id:
                return i
        return {}

    @classmethod
    def update_incident(cls, inc_id, status, notes=""):
        for i in cls._incidents:
            if i.get("id") == inc_id:
                i["status"] = status
                i["notes"]  = notes
                if status in ("resolved", "mitigated"):
                    i["resolved_at"] = datetime.now().isoformat()

    @classmethod
    def insert_audit(cls, entry):
        entry = dict(entry)
        entry["id"]          = len(cls._audit) + 1
        entry["executed_at"] = datetime.now().isoformat()
        cls._audit.append(entry)
        return entry["id"]

    @classmethod
    def query_audit(cls, incident_id=None, limit=50):
        results = list(reversed(cls._audit))
        if incident_id:
            results = [a for a in results if a.get("incident_id") == incident_id]
        return results[:limit]

    @classmethod
    def init_all(cls):
        pass


if not DB_AVAILABLE:
    db = MockDB()

    def suggest_actions(inc):
        t    = inc.get("threat_type", "")
        ip   = inc.get("source_ip", "")
        user = inc.get("affected_user", "")
        actions = {
            "SSH Brute Force": [
                f"iptables -A INPUT -s {ip} -j DROP" if ip else "Block attacking IP",
                f"passwd -l {user}" if user else "Audit SSH accounts",
                "Disable password auth in sshd_config",
            ],
            "Root Login": [
                "Set PermitRootLogin no in /etc/ssh/sshd_config",
                "Enforce sudo usage",
            ],
        }
        return actions.get(t, ["Investigate logs manually", "Escalate to senior admin"])

    def handle_new_incident(inc):
        pass


# ─── Safe command whitelist ───────────────────────────────────────────────────
SAFE_COMMANDS = [
    "iptables", "ufw", "passwd", "userdel", "usermod",
    "systemctl", "pkill", "kill", "ss", "netstat",
    "who", "last", "journalctl", "smartctl", "fsck",
    "free", "vmstat", "fail2ban-client",
]


def is_safe_cmd(cmd):
    try:
        parts = shlex.split(cmd)
    except Exception:
        return False
    if not parts:
        return False
    return os.path.basename(parts[0]) in SAFE_COMMANDS


# ═══════════════════════════════════════════════════════════════════════════════
#  STYLED WIDGETS
# ═══════════════════════════════════════════════════════════════════════════════

class StyledButton(tk.Button):
    def __init__(self, parent, text, command=None, style="primary", **kwargs):
        styles = {
            "primary": {"bg": C["accent2"],  "fg": C["bg"],    "abg": C["accent"]},
            "danger":  {"bg": C["red2"],      "fg": C["white"], "abg": C["red"]},
            "success": {"bg": "#006644",      "fg": C["green"], "abg": "#008855"},
            "ghost":   {"bg": C["bg3"],       "fg": C["text"],  "abg": C["border"]},
            "warning": {"bg": "#664400",      "fg": C["orange"],"abg": "#885500"},
        }
        s = styles.get(style, styles["primary"])
        super().__init__(
            parent, text=text, command=command,
            bg=s["bg"], fg=s["fg"],
            activebackground=s["abg"],
            activeforeground=s["fg"],
            relief="flat", bd=0,
            padx=14, pady=7,
            cursor="hand2",
            font=("Courier New", 9, "bold"),
            **kwargs
        )


class Card(tk.Frame):
    def __init__(self, parent, title=None, **kwargs):
        super().__init__(
            parent,
            bg=C["panel"],
            highlightbackground=C["border"],
            highlightthickness=1,
            **kwargs
        )
        if title:
            hdr = tk.Frame(self, bg=C["bg3"], pady=6)
            hdr.pack(fill="x")
            tk.Label(
                hdr, text=title,
                bg=C["bg3"], fg=C["accent"],
                font=("Courier New", 9, "bold"),
                padx=12
            ).pack(side="left")


class SeverityBadge(tk.Label):
    def __init__(self, parent, severity, **kwargs):
        color = sev_color(severity)
        super().__init__(
            parent,
            text=f" {severity.upper()} ",
            bg=color, fg=C["bg"],
            font=("Courier New", 8, "bold"),
            padx=4, pady=2,
            **kwargs
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  ALERT POPUP
# ═══════════════════════════════════════════════════════════════════════════════

class AlertPopup(tk.Toplevel):
    def __init__(self, parent, incident: dict):
        super().__init__(parent)
        sev    = incident.get("severity", "high").lower()
        threat = incident.get("threat_type", "Unknown Threat")
        inc_id = incident.get("id", "?")
        desc   = incident.get("description", "")
        ip     = incident.get("source_ip", "")
        user   = incident.get("affected_user", "")
        ts     = fmt_time(incident.get("detected_at", datetime.now().isoformat()))
        color  = sev_color(sev)

        self.title(f"InsightLog Alert — Incident #{inc_id}")
        self.configure(bg=C["bg"])
        self.geometry("520x380")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.lift()
        self.focus_force()

        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"520x380+{(sw-520)//2}+{(sh-380)//2}")

        # Header
        hdr = tk.Frame(self, bg=color, pady=14)
        hdr.pack(fill="x")
        tk.Label(
            hdr, text="  SECURITY ALERT DETECTED",
            bg=color, fg=C["bg"],
            font=("Courier New", 13, "bold")
        ).pack()
        tk.Label(
            hdr, text=f"Incident #{inc_id}  •  {sev.upper()}",
            bg=color, fg=C["bg"],
            font=("Courier New", 9)
        ).pack()

        # Body
        body = tk.Frame(self, bg=C["bg"], padx=24, pady=16)
        body.pack(fill="both", expand=True)

        def row(label, value, val_color=C["white"]):
            f = tk.Frame(body, bg=C["bg"])
            f.pack(fill="x", pady=3)
            tk.Label(
                f, text=f"{label:<14}",
                bg=C["bg"], fg=C["subtext"],
                font=("Courier New", 9), width=14, anchor="w"
            ).pack(side="left")
            tk.Label(
                f, text=value,
                bg=C["bg"], fg=val_color,
                font=("Courier New", 9, "bold"), anchor="w"
            ).pack(side="left")

        row("Threat",   threat,    color)
        row("Severity", sev.upper(), color)
        row("Details",  desc[:60] + ("..." if len(desc) > 60 else ""), C["text"])
        if ip:   row("Source IP",  ip,   C["orange"])
        if user: row("User",       user, C["yellow"])
        row("Detected", ts, C["subtext"])

        tk.Frame(body, bg=C["border"], height=1).pack(fill="x", pady=10)
        tk.Label(
            body,
            text=f"insightlog respond --incident {inc_id}",
            bg=C["bg2"], fg=C["accent"],
            font=("Courier New", 9),
            padx=8, pady=4
        ).pack(fill="x")

        # Buttons
        btn_frame = tk.Frame(self, bg=C["bg"], padx=24, pady=14)
        btn_frame.pack(fill="x")

        StyledButton(
            btn_frame, "  Respond Now  ",
            command=lambda: self._respond(parent, inc_id),
            style="danger"
        ).pack(side="left", padx=(0, 8))
        StyledButton(
            btn_frame, "  View Incident  ",
            command=lambda: self._view(parent, inc_id),
            style="primary"
        ).pack(side="left", padx=(0, 8))
        StyledButton(
            btn_frame, "  Dismiss  ",
            command=self.destroy,
            style="ghost"
        ).pack(side="right")

        self._countdown = 30
        self._timer_label = tk.Label(
            btn_frame, text=f"Auto-close in {self._countdown}s",
            bg=C["bg"], fg=C["subtext"],
            font=("Courier New", 8)
        )
        self._timer_label.pack(side="right", padx=8)
        self._tick()

    def _tick(self):
        self._countdown -= 1
        if self._countdown <= 0:
            self.destroy()
            return
        self._timer_label.config(text=f"Auto-close in {self._countdown}s")
        self.after(1000, self._tick)

    def _respond(self, parent, inc_id):
        self.destroy()
        if hasattr(parent, "open_respond_dialog"):
            parent.open_respond_dialog(inc_id)

    def _view(self, parent, inc_id):
        self.destroy()
        if hasattr(parent, "show_incident_detail"):
            parent.show_incident_detail(inc_id)


# ═══════════════════════════════════════════════════════════════════════════════
#  RESPOND DIALOG
# ═══════════════════════════════════════════════════════════════════════════════

class RespondDialog(tk.Toplevel):
    def __init__(self, parent, inc_id: int):
        super().__init__(parent)
        self.inc_id  = inc_id
        self.inc     = db.get_incident(inc_id) or {}
        self.actions = suggest_actions(self.inc)

        self.title(f"Respond to Incident #{inc_id}")
        self.configure(bg=C["bg"])
        self.geometry("620x580")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self._build()

    def _build(self):
        # Header
        hdr = tk.Frame(self, bg=C["red2"], pady=10)
        hdr.pack(fill="x")
        tk.Label(
            hdr,
            text=f"  Incident #{self.inc_id} — {self.inc.get('threat_type','Unknown')}",
            bg=C["red2"], fg=C["white"],
            font=("Courier New", 11, "bold")
        ).pack(side="left", padx=12)

        body = tk.Frame(self, bg=C["bg"], padx=20, pady=14)
        body.pack(fill="both", expand=True)

        # Summary
        info = tk.Frame(body, bg=C["bg2"], padx=12, pady=10)
        info.pack(fill="x", pady=(0, 14))
        tk.Label(
            info,
            text=self.inc.get("description", ""),
            bg=C["bg2"], fg=C["text"],
            font=("Courier New", 9),
            wraplength=560, justify="left"
        ).pack(anchor="w")

        # Suggested actions
        tk.Label(
            body, text="SUGGESTED ACTIONS",
            bg=C["bg"], fg=C["accent"],
            font=("Courier New", 9, "bold")
        ).pack(anchor="w", pady=(0, 6))

        for i, action in enumerate(self.actions):
            cmd_text = action.split(":", 1)[1].strip() if ":" in action else action
            f = tk.Frame(
                body, bg=C["bg3"],
                highlightbackground=C["border"], highlightthickness=1
            )
            f.pack(fill="x", pady=3)
            tk.Label(
                f, text=f"  {i+1}.",
                bg=C["bg3"], fg=C["subtext"],
                font=("Courier New", 9), width=4
            ).pack(side="left")
            tk.Label(
                f, text=action[:65],
                bg=C["bg3"], fg=C["text"],
                font=("Courier New", 9), anchor="w"
            ).pack(side="left", fill="x", expand=True, padx=4)
            StyledButton(
                f, "Execute",
                command=lambda c=cmd_text: self._confirm_execute(c),
                style="danger"
            ).pack(side="right", padx=6, pady=4)

        # Custom command
        tk.Label(
            body, text="CUSTOM COMMAND",
            bg=C["bg"], fg=C["accent"],
            font=("Courier New", 9, "bold")
        ).pack(anchor="w", pady=(14, 6))

        cmd_row = tk.Frame(body, bg=C["bg"])
        cmd_row.pack(fill="x")
        self.custom_entry = tk.Entry(
            cmd_row,
            bg=C["bg3"], fg=C["accent"],
            insertbackground=C["accent"],
            font=("Courier New", 10),
            relief="flat",
            highlightbackground=C["border"],
            highlightthickness=1
        )
        self.custom_entry.pack(side="left", fill="x", expand=True, padx=(0, 8), ipady=6)
        StyledButton(
            cmd_row, "Run",
            command=self._run_custom,
            style="warning"
        ).pack(side="right")

        # Output
        tk.Label(
            body, text="OUTPUT",
            bg=C["bg"], fg=C["accent"],
            font=("Courier New", 9, "bold")
        ).pack(anchor="w", pady=(14, 4))

        self.output = scrolledtext.ScrolledText(
            body, height=6,
            bg=C["bg2"], fg=C["green"],
            font=("Courier New", 9),
            relief="flat",
            insertbackground=C["green"],
            state="disabled"
        )
        self.output.pack(fill="x")

        # Bottom buttons
        btn_row = tk.Frame(self, bg=C["bg"], padx=20, pady=12)
        btn_row.pack(fill="x")
        StyledButton(
            btn_row, "  Mark Resolved  ",
            command=self._resolve,
            style="success"
        ).pack(side="left", padx=(0, 8))
        StyledButton(
            btn_row, "  Close  ",
            command=self.destroy,
            style="ghost"
        ).pack(side="right")

    def _log_output(self, text):
        self.output.config(state="normal")
        self.output.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
        self.output.see("end")
        self.output.config(state="disabled")

    def _confirm_execute(self, cmd):
        if not messagebox.askyesno(
            "Confirm Execution",
            f"Execute this command?\n\n{cmd}\n\nThis action will be logged to D3.",
            parent=self
        ):
            return
        self._execute(cmd)

    def _run_custom(self):
        cmd = self.custom_entry.get().strip()
        if not cmd:
            return
        if not is_safe_cmd(cmd):
            messagebox.showerror("Blocked", f"Command not in safe list:\n{cmd}", parent=self)
            return
        self._confirm_execute(cmd)

    def _execute(self, cmd):
        self._log_output(f"$ {cmd}")
        try:
            proc = subprocess.run(
                shlex.split(cmd),
                capture_output=True, text=True, timeout=30
            )
            out     = (proc.stdout + proc.stderr).strip()
            success = proc.returncode == 0
            self._log_output(out or "(no output)")
            db.insert_audit({
                "incident_id": self.inc_id,
                "action_type": "execute",
                "command":     cmd,
                "result":      out[:2000],
                "approved_by": "operator",
                "success":     1 if success else 0,
            })
        except subprocess.TimeoutExpired:
            self._log_output("Command timed out after 30s.")
        except Exception as e:
            self._log_output(f"Error: {e}")

    def _resolve(self):
        db.update_incident(self.inc_id, "resolved", "Resolved via GUI")
        db.insert_audit({
            "incident_id": self.inc_id,
            "action_type": "resolve",
            "command":     "gui_resolve",
            "result":      "Resolved by operator",
            "approved_by": "operator",
            "success":     1,
        })
        self._log_output(f"Incident #{self.inc_id} marked as resolved.")
        messagebox.showinfo("Resolved", f"Incident #{self.inc_id} resolved.", parent=self)


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

class InsightLogApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("InsightLog — Security Monitoring Dashboard")
        self.configure(bg=C["bg"])
        self.geometry("1280x800")
        self.minsize(1100, 700)

        # ── Initialize state variables FIRST before building UI ──
        self._tailers      = []
        self._alert_queue  = []
        self._alert_lock   = threading.Lock()
        self._current_page = "dashboard"
        self._status_var   = tk.StringVar(value="  Ready")

        # Initialize DB
        try:
            db.init_all()
        except Exception as e:
            print(f"[DB] Warning: {e}")

        # ── Build UI ──
        self._build_ui()
        self._start_daemon()
        self._refresh_loop()

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_titlebar()
        self._build_sidebar()
        self._build_statusbar()   # statusbar BEFORE main (uses _status_var)
        self._build_main()

    def _build_titlebar(self):
        bar = tk.Frame(
            self, bg=C["bg2"], height=52,
            highlightbackground=C["border"], highlightthickness=1
        )
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        tk.Label(
            bar, text="◈ InsightLog",
            bg=C["bg2"], fg=C["accent"],
            font=("Courier New", 15, "bold"), padx=20
        ).pack(side="left", pady=10)

        tk.Label(
            bar, text="Linux Security Monitoring & Incident Response",
            bg=C["bg2"], fg=C["subtext"],
            font=("Courier New", 9)
        ).pack(side="left")

        self._clock_var = tk.StringVar()
        tk.Label(
            bar, textvariable=self._clock_var,
            bg=C["bg2"], fg=C["subtext"],
            font=("Courier New", 9), padx=16
        ).pack(side="right")
        self._update_clock()

        self._daemon_dot = tk.Label(
            bar, text="⬤  MONITORING",
            bg=C["bg2"], fg=C["green"],
            font=("Courier New", 9, "bold"), padx=16
        )
        self._daemon_dot.pack(side="right")

    def _build_statusbar(self):
        bar = tk.Frame(
            self, bg=C["bg2"], height=26,
            highlightbackground=C["border"], highlightthickness=1
        )
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        tk.Label(
            bar, textvariable=self._status_var,
            bg=C["bg2"], fg=C["subtext"],
            font=("Courier New", 8), padx=12
        ).pack(side="left", pady=4)

        tk.Label(
            bar, text="D1: Logs  |  D2: Incidents  |  D3: Audit",
            bg=C["bg2"], fg=C["subtext"],
            font=("Courier New", 8), padx=12
        ).pack(side="right", pady=4)

    def _build_sidebar(self):
        self.sidebar = tk.Frame(
            self, bg=C["bg2"], width=200,
            highlightbackground=C["border"], highlightthickness=1
        )
        self.sidebar.pack(fill="y", side="left")
        self.sidebar.pack_propagate(False)

        tk.Frame(self.sidebar, bg=C["border"], height=1).pack(fill="x")

        nav_items = [
            ("◈  Dashboard",   self._show_dashboard),
            ("⚠  Incidents",   self._show_incidents),
            ("▤  Logs",        self._show_logs),
            ("⚙  Respond",     self._show_respond),
            ("◷  Postmortem",  self._show_postmortem),
            ("▣  Audit Trail", self._show_audit),
        ]

        self._nav_btns = []
        for label, cmd in nav_items:
            btn = tk.Button(
                self.sidebar, text=label,
                bg=C["bg2"], fg=C["text"],
                activebackground=C["bg3"],
                activeforeground=C["accent"],
                relief="flat", bd=0,
                padx=20, pady=12,
                anchor="w", cursor="hand2",
                font=("Courier New", 9),
                command=cmd
            )
            btn.pack(fill="x")
            self._nav_btns.append(btn)

        tk.Frame(self.sidebar, bg=C["border"], height=1).pack(fill="x", pady=8)

        self._stats_frame = tk.Frame(self.sidebar, bg=C["bg2"], padx=12)
        self._stats_frame.pack(fill="x", pady=4)

        tk.Label(
            self._stats_frame, text="LIVE STATS",
            bg=C["bg2"], fg=C["subtext"],
            font=("Courier New", 8, "bold")
        ).pack(anchor="w", pady=(0, 6))

        self._stat_vars = {}
        for label in ["Total Logs", "Open Incidents", "Critical", "High"]:
            f = tk.Frame(self._stats_frame, bg=C["bg2"])
            f.pack(fill="x", pady=2)
            tk.Label(
                f, text=label,
                bg=C["bg2"], fg=C["subtext"],
                font=("Courier New", 8), anchor="w"
            ).pack(side="left")
            var = tk.StringVar(value="—")
            self._stat_vars[label] = var
            clr = C["red"]    if "Critical" in label else \
                  C["orange"] if "High"     in label else C["text"]
            tk.Label(
                f, textvariable=var,
                bg=C["bg2"], fg=clr,
                font=("Courier New", 8, "bold"), anchor="e"
            ).pack(side="right")

    def _build_main(self):
        self.main = tk.Frame(self, bg=C["bg"])
        self.main.pack(fill="both", expand=True, side="left")

        self._pages = {}
        for name in ["dashboard", "incidents", "logs", "respond", "postmortem", "audit"]:
            f = tk.Frame(self.main, bg=C["bg"])
            self._pages[name] = f

        self._build_dashboard()
        self._build_incidents_page()
        self._build_logs_page()
        self._build_respond_page()
        self._build_postmortem_page()
        self._build_audit_page()

        self._show_dashboard()

    # ── Pages ─────────────────────────────────────────────────────────────────

    def _build_dashboard(self):
        page = self._pages["dashboard"]
        page.columnconfigure((0,1,2,3), weight=1)
        page.rowconfigure(2, weight=1)

        tk.Label(
            page, text="DASHBOARD",
            bg=C["bg"], fg=C["accent"],
            font=("Courier New", 11, "bold"),
            padx=20, pady=14
        ).grid(row=0, column=0, columnspan=4, sticky="w")

        stat_defs = [
            ("Total Logs",     C["accent"],  "▤"),
            ("Open Incidents", C["red"],     "⚠"),
            ("Critical",       C["critical"],"⬤"),
            ("Resolved Today", C["green"],   "✓"),
        ]
        self._dash_stat_vars = {}
        for col, (label, color, icon) in enumerate(stat_defs):
            card = tk.Frame(
                page, bg=C["panel"],
                highlightbackground=color,
                highlightthickness=1,
                padx=20, pady=16
            )
            card.grid(row=1, column=col, padx=6, pady=(0,8), sticky="nsew")
            tk.Label(card, text=icon,  bg=C["panel"], fg=color, font=("Courier New", 20)).pack(anchor="w")
            var = tk.StringVar(value="0")
            self._dash_stat_vars[label] = var
            tk.Label(card, textvariable=var, bg=C["panel"], fg=color, font=("Courier New", 24, "bold")).pack(anchor="w")
            tk.Label(card, text=label,       bg=C["panel"], fg=C["subtext"], font=("Courier New", 8)).pack(anchor="w")

        # Recent incidents
        inc_card = Card(page, title="▸ RECENT INCIDENTS")
        inc_card.grid(row=2, column=0, columnspan=3, padx=(6,3), pady=4, sticky="nsew")
        cols = ("ID", "Severity", "Threat", "IP", "Status", "Time")
        self._dash_inc_tree = self._make_tree(inc_card, cols, heights=10)

        # Live feed
        log_card = Card(page, title="▸ LIVE LOG FEED")
        log_card.grid(row=2, column=3, padx=(3,6), pady=4, sticky="nsew")
        self._live_feed = scrolledtext.ScrolledText(
            log_card, bg=C["bg2"], fg=C["green"],
            font=("Courier New", 8),
            relief="flat", state="disabled", height=10
        )
        self._live_feed.pack(fill="both", expand=True, padx=8, pady=8)
        self._live_feed.tag_config("auth",  foreground=C["orange"])
        self._live_feed.tag_config("error", foreground=C["red"])
        self._live_feed.tag_config("warn",  foreground=C["yellow"])
        self._live_feed.tag_config("info",  foreground=C["green"])

    def _build_incidents_page(self):
        page = self._pages["incidents"]

        hdr = tk.Frame(page, bg=C["bg"])
        hdr.pack(fill="x", padx=16, pady=12)
        tk.Label(hdr, text="INCIDENTS", bg=C["bg"], fg=C["accent"],
                 font=("Courier New", 11, "bold")).pack(side="left")

        fbar = tk.Frame(hdr, bg=C["bg"])
        fbar.pack(side="right")
        tk.Label(fbar, text="Status:", bg=C["bg"], fg=C["subtext"],
                 font=("Courier New", 9)).pack(side="left", padx=(0,4))
        self._inc_status_var = tk.StringVar(value="open")
        cb = ttk.Combobox(
            fbar, textvariable=self._inc_status_var,
            values=["open", "mitigated", "resolved", "all"],
            width=10, state="readonly", font=("Courier New", 9)
        )
        cb.pack(side="left", padx=(0,8))
        cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_incidents())
        StyledButton(fbar, "⟳ Refresh", command=self._refresh_incidents, style="ghost").pack(side="left")

        card = Card(page)
        card.pack(fill="both", expand=True, padx=16, pady=(0,8))
        cols = ("ID", "Severity", "Threat Type", "Source IP", "User", "Status", "Detected At")
        self._inc_tree = self._make_tree(card, cols, heights=18)
        self._inc_tree.bind("<Double-1>", self._on_incident_dbl)

        btn_row = tk.Frame(page, bg=C["bg"])
        btn_row.pack(fill="x", padx=16, pady=(0,8))
        StyledButton(btn_row, "  View Details  ", command=self._view_selected_incident, style="primary").pack(side="left", padx=(0,6))
        StyledButton(btn_row, "  Respond  ",      command=self._respond_selected,       style="danger").pack(side="left", padx=(0,6))
        StyledButton(btn_row, "  Mark Resolved  ",command=self._resolve_selected,       style="success").pack(side="left")

    def _build_logs_page(self):
        page = self._pages["logs"]

        hdr = tk.Frame(page, bg=C["bg"])
        hdr.pack(fill="x", padx=16, pady=12)
        tk.Label(hdr, text="LOG DATABASE  (D1)", bg=C["bg"], fg=C["accent"],
                 font=("Courier New", 11, "bold")).pack(side="left")

        fbar = tk.Frame(hdr, bg=C["bg"])
        fbar.pack(side="right")
        tk.Label(fbar, text="Type:", bg=C["bg"], fg=C["subtext"],
                 font=("Courier New", 9)).pack(side="left", padx=(0,4))
        self._log_type_var = tk.StringVar(value="all")
        ttk.Combobox(
            fbar, textvariable=self._log_type_var,
            values=["all","auth","syslog"],
            width=8, state="readonly", font=("Courier New", 9)
        ).pack(side="left", padx=(0,8))
        tk.Label(fbar, text="Search:", bg=C["bg"], fg=C["subtext"],
                 font=("Courier New", 9)).pack(side="left", padx=(0,4))
        self._log_search_var = tk.StringVar()
        tk.Entry(
            fbar, textvariable=self._log_search_var,
            bg=C["bg3"], fg=C["accent"], insertbackground=C["accent"],
            font=("Courier New", 9), relief="flat",
            highlightbackground=C["border"], highlightthickness=1, width=20
        ).pack(side="left", padx=(0,8), ipady=4)
        StyledButton(fbar, "Search", command=self._refresh_logs, style="primary").pack(side="left")

        card = Card(page)
        card.pack(fill="both", expand=True, padx=16, pady=(0,8))
        cols = ("ID", "Time", "Type", "Host", "Process", "Message")
        self._log_tree = self._make_tree(card, cols, heights=20)
        self._log_tree.column("Message", width=380)

    def _build_respond_page(self):
        page = self._pages["respond"]

        tk.Label(page, text="INCIDENT RESPONSE", bg=C["bg"], fg=C["accent"],
                 font=("Courier New", 11, "bold"), padx=16, pady=12).pack(anchor="w")

        sel = tk.Frame(page, bg=C["bg2"], highlightbackground=C["border"], highlightthickness=1)
        sel.pack(fill="x", padx=16, pady=(0,10))
        inner = tk.Frame(sel, bg=C["bg2"], padx=14, pady=10)
        inner.pack(fill="x")
        tk.Label(inner, text="Incident ID:", bg=C["bg2"], fg=C["subtext"],
                 font=("Courier New", 9)).pack(side="left")
        self._respond_inc_var = tk.StringVar()
        tk.Entry(
            inner, textvariable=self._respond_inc_var,
            bg=C["bg3"], fg=C["accent"], insertbackground=C["accent"],
            font=("Courier New", 10), relief="flat",
            highlightbackground=C["border"], highlightthickness=1, width=8
        ).pack(side="left", padx=8, ipady=4)
        StyledButton(inner, "Load Incident", command=self._load_respond_incident, style="primary").pack(side="left")

        self._respond_detail = tk.Label(
            page, text="No incident loaded.",
            bg=C["bg"], fg=C["subtext"],
            font=("Courier New", 9), padx=16, pady=6, anchor="w"
        )
        self._respond_detail.pack(fill="x")

        tk.Label(page, text="SUGGESTED ACTIONS", bg=C["bg"], fg=C["accent"],
                 font=("Courier New", 9, "bold"), padx=16).pack(anchor="w", pady=(8,4))
        self._suggest_frame = tk.Frame(page, bg=C["bg"])
        self._suggest_frame.pack(fill="x", padx=16)

        tk.Label(page, text="CUSTOM COMMAND", bg=C["bg"], fg=C["accent"],
                 font=("Courier New", 9, "bold"), padx=16).pack(anchor="w", pady=(12,4))
        cmd_row = tk.Frame(page, bg=C["bg"], padx=16)
        cmd_row.pack(fill="x")
        self._custom_cmd_var = tk.StringVar()
        tk.Entry(
            cmd_row, textvariable=self._custom_cmd_var,
            bg=C["bg3"], fg=C["accent"], insertbackground=C["accent"],
            font=("Courier New", 10), relief="flat",
            highlightbackground=C["border"], highlightthickness=1
        ).pack(side="left", fill="x", expand=True, padx=(0,8), ipady=6)
        StyledButton(cmd_row, "Execute", command=self._run_custom_cmd, style="warning").pack(side="right")

        tk.Label(page, text="OUTPUT CONSOLE", bg=C["bg"], fg=C["accent"],
                 font=("Courier New", 9, "bold"), padx=16).pack(anchor="w", pady=(12,4))
        self._respond_output = scrolledtext.ScrolledText(
            page, height=8,
            bg=C["bg2"], fg=C["green"],
            font=("Courier New", 9), relief="flat",
            insertbackground=C["green"], state="disabled"
        )
        self._respond_output.pack(fill="x", padx=16, pady=(0,12))
        self._current_respond_inc = None

    def _build_postmortem_page(self):
        page = self._pages["postmortem"]

        hdr = tk.Frame(page, bg=C["bg"])
        hdr.pack(fill="x", padx=16, pady=12)
        tk.Label(hdr, text="POSTMORTEM ANALYSIS", bg=C["bg"], fg=C["accent"],
                 font=("Courier New", 11, "bold")).pack(side="left")
        ctrl = tk.Frame(hdr, bg=C["bg"])
        ctrl.pack(side="right")
        tk.Label(ctrl, text="Days:", bg=C["bg"], fg=C["subtext"],
                 font=("Courier New", 9)).pack(side="left")
        self._pm_days_var = tk.StringVar(value="7")
        ttk.Combobox(
            ctrl, textvariable=self._pm_days_var,
            values=["1","3","7","14","30"],
            width=4, state="readonly"
        ).pack(side="left", padx=6)
        StyledButton(ctrl, "Analyze", command=self._run_postmortem, style="primary").pack(side="left")

        card = Card(page, title="▸ ANALYSIS REPORT")
        card.pack(fill="both", expand=True, padx=16, pady=(0,8))
        self._pm_output = scrolledtext.ScrolledText(
            card, bg=C["bg2"], fg=C["text"],
            font=("Courier New", 9), relief="flat", state="disabled"
        )
        self._pm_output.pack(fill="both", expand=True, padx=8, pady=8)
        self._pm_output.tag_config("header",   foreground=C["accent"], font=("Courier New", 10, "bold"))
        self._pm_output.tag_config("label",    foreground=C["subtext"])
        self._pm_output.tag_config("value",    foreground=C["white"])
        self._pm_output.tag_config("critical", foreground=C["critical"])
        self._pm_output.tag_config("high",     foreground=C["high"])
        self._pm_output.tag_config("medium",   foreground=C["medium"])
        self._pm_output.tag_config("green",    foreground=C["green"])

    def _build_audit_page(self):
        page = self._pages["audit"]

        hdr = tk.Frame(page, bg=C["bg"])
        hdr.pack(fill="x", padx=16, pady=12)
        tk.Label(hdr, text="AUDIT TRAIL  (D3)", bg=C["bg"], fg=C["accent"],
                 font=("Courier New", 11, "bold")).pack(side="left")
        StyledButton(hdr, "⟳ Refresh", command=self._refresh_audit, style="ghost").pack(side="right")

        card = Card(page)
        card.pack(fill="both", expand=True, padx=16, pady=(0,8))
        cols = ("ID", "Incident", "Action", "Command", "Result", "OK", "Time")
        self._audit_tree = self._make_tree(card, cols, heights=20)
        self._audit_tree.column("Command", width=200)
        self._audit_tree.column("Result",  width=200)

    # ── Tree Helper ───────────────────────────────────────────────────────────

    def _make_tree(self, parent, columns, heights=12):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dark.Treeview",
            background=C["bg2"], foreground=C["text"],
            fieldbackground=C["bg2"], rowheight=26,
            font=("Courier New", 8), borderwidth=0)
        style.configure("Dark.Treeview.Heading",
            background=C["bg3"], foreground=C["accent"],
            font=("Courier New", 8, "bold"), borderwidth=0, relief="flat")
        style.map("Dark.Treeview",
            background=[("selected", C["border"])],
            foreground=[("selected", C["white"])])

        frame = tk.Frame(parent, bg=C["bg2"])
        frame.pack(fill="both", expand=True, padx=8, pady=8)

        tree = ttk.Treeview(
            frame, columns=columns, show="headings",
            height=heights, style="Dark.Treeview"
        )
        for col in columns:
            w = 80
            if col in ("Message", "Description", "Command", "Result"): w = 260
            elif col in ("Threat", "Threat Type"): w = 180
            elif col in ("Time", "Detected At"):   w = 140
            elif col in ("ID", "OK"):              w = 40
            tree.heading(col, text=col)
            tree.column(col, width=w, anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        return tree

    # ── Navigation ────────────────────────────────────────────────────────────

    def _show_page(self, name):
        for f in self._pages.values():
            f.pack_forget()
        self._pages[name].pack(fill="both", expand=True)
        self._current_page = name

    def _show_dashboard(self):
        self._show_page("dashboard")
        self._refresh_dashboard()

    def _show_incidents(self):
        self._show_page("incidents")
        self._refresh_incidents()

    def _show_logs(self):
        self._show_page("logs")
        self._refresh_logs()

    def _show_respond(self):
        self._show_page("respond")

    def _show_postmortem(self):
        self._show_page("postmortem")
        self._run_postmortem()

    def _show_audit(self):
        self._show_page("audit")
        self._refresh_audit()

    # ── Data Refresh ──────────────────────────────────────────────────────────

    def _refresh_dashboard(self):
        try:
            stats     = db.get_log_stats()
            incidents = db.query_incidents(limit=500)
            open_inc  = [i for i in incidents if i.get("status") == "open"]
            critical  = [i for i in open_inc  if i.get("severity") == "critical"]
            today     = datetime.now().date().isoformat()
            resolved  = [i for i in incidents
                         if i.get("status") == "resolved"
                         and (i.get("resolved_at") or "").startswith(today)]

            self._dash_stat_vars["Total Logs"].set(str(stats.get("total", 0)))
            self._dash_stat_vars["Open Incidents"].set(str(len(open_inc)))
            self._dash_stat_vars["Critical"].set(str(len(critical)))
            self._dash_stat_vars["Resolved Today"].set(str(len(resolved)))

            self._stat_vars["Total Logs"].set(str(stats.get("total", 0)))
            self._stat_vars["Open Incidents"].set(str(len(open_inc)))
            self._stat_vars["Critical"].set(str(len(critical)))
            self._stat_vars["High"].set(str(
                len([i for i in open_inc if i.get("severity") == "high"])
            ))

            self._dash_inc_tree.delete(*self._dash_inc_tree.get_children())
            for inc in incidents[:10]:
                sev = (inc.get("severity") or "").lower()
                self._dash_inc_tree.insert("", "end",
                    values=(
                        f"#{inc.get('id','')}",
                        (inc.get("severity") or "").upper(),
                        inc.get("threat_type",""),
                        inc.get("source_ip","") or "—",
                        inc.get("status",""),
                        fmt_time(inc.get("detected_at","")),
                    ), tags=(sev,))
            self._dash_inc_tree.tag_configure("critical", foreground=C["critical"])
            self._dash_inc_tree.tag_configure("high",     foreground=C["high"])
            self._dash_inc_tree.tag_configure("medium",   foreground=C["medium"])

        except Exception as e:
            self._set_status(f"Dashboard refresh error: {e}")

    def _refresh_incidents(self):
        try:
            status  = self._inc_status_var.get()
            filters = {} if status == "all" else {"status": status}
            rows    = db.query_incidents(filters, limit=200)

            self._inc_tree.delete(*self._inc_tree.get_children())
            for inc in rows:
                sev = (inc.get("severity") or "").lower()
                self._inc_tree.insert("", "end",
                    values=(
                        inc.get("id",""),
                        (inc.get("severity") or "").upper(),
                        inc.get("threat_type",""),
                        inc.get("source_ip","")      or "—",
                        inc.get("affected_user","")  or "—",
                        inc.get("status",""),
                        fmt_time(inc.get("detected_at","")),
                    ), tags=(sev,))
            self._inc_tree.tag_configure("critical", foreground=C["critical"])
            self._inc_tree.tag_configure("high",     foreground=C["high"])
            self._inc_tree.tag_configure("medium",   foreground=C["medium"])
            self._set_status(f"{len(rows)} incidents loaded.")
        except Exception as e:
            self._set_status(f"Error: {e}")

    def _refresh_logs(self):
        try:
            filters = {}
            lt = self._log_type_var.get()
            if lt != "all": filters["log_type"] = lt
            kw = self._log_search_var.get().strip()
            if kw: filters["keyword"] = kw

            rows = db.query_logs(filters, limit=300)
            self._log_tree.delete(*self._log_tree.get_children())
            for r in rows:
                self._log_tree.insert("", "end",
                    values=(
                        r.get("id",""),
                        fmt_time(r.get("timestamp","")),
                        r.get("log_type",""),
                        r.get("host",""),
                        (r.get("process","") or "")[:18],
                        (r.get("message","") or "")[:80],
                    ), tags=(r.get("log_type",""),))
            self._log_tree.tag_configure("auth",   foreground=C["orange"])
            self._log_tree.tag_configure("syslog", foreground=C["text"])
            self._set_status(f"{len(rows)} log entries loaded.")
        except Exception as e:
            self._set_status(f"Error: {e}")

    def _refresh_audit(self):
        try:
            rows = db.query_audit(limit=200)
            self._audit_tree.delete(*self._audit_tree.get_children())
            for r in rows:
                ok = "✓" if r.get("success") else "✗"
                self._audit_tree.insert("", "end",
                    values=(
                        r.get("id",""),
                        f"#{r.get('incident_id','')}",
                        r.get("action_type",""),
                        (r.get("command","") or "")[:40],
                        (r.get("result","")  or "")[:50],
                        ok,
                        fmt_time(r.get("executed_at","")),
                    ), tags=("ok" if r.get("success") else "fail",))
            self._audit_tree.tag_configure("ok",   foreground=C["green"])
            self._audit_tree.tag_configure("fail", foreground=C["red"])
        except Exception as e:
            self._set_status(f"Error: {e}")

    def _run_postmortem(self):
        try:
            days      = int(self._pm_days_var.get())
            since     = (datetime.now() - timedelta(days=days)).isoformat()
            incidents = [i for i in db.query_incidents(limit=1000)
                         if (i.get("detected_at") or "") >= since]
            logs      = db.query_logs(limit=1000)

            open_ = sum(1 for i in incidents if i.get("status") == "open")
            res   = sum(1 for i in incidents if i.get("status") in ("resolved","mitigated"))

            by_sev  = defaultdict(int)
            by_type = defaultdict(int)
            top_ips = defaultdict(int)
            top_usr = defaultdict(int)

            for inc in incidents:
                by_sev[inc.get("severity","unknown")]   += 1
                by_type[inc.get("threat_type","unknown")] += 1
                if inc.get("source_ip"):      top_ips[inc["source_ip"]]      += 1
                if inc.get("affected_user"):  top_usr[inc["affected_user"]]  += 1

            out = self._pm_output
            out.config(state="normal")
            out.delete("1.0", "end")

            def w(text, tag=None):
                out.insert("end", text + "\n", tag)

            w(f"{'═'*55}",                                 "header")
            w(f"  POSTMORTEM ANALYSIS — Last {days} days", "header")
            w(f"  {fmt_time(since)}  →  now",              "label")
            w(f"{'═'*55}\n",                               "header")
            w(f"  Incidents    : {len(incidents)} total",  "value")
            w(f"  Open         : {open_}",                 "value")
            w(f"  Resolved     : {res}",                   "green")
            w(f"  Log Entries  : {len(logs)}\n",           "value")

            w("  BY SEVERITY", "header")
            for sev in ["critical","high","medium","low"]:
                cnt = by_sev.get(sev, 0)
                if cnt: w(f"    {sev.upper():<12}: {cnt}", sev)

            if by_type:
                w("\n  TOP THREAT TYPES", "header")
                for t, cnt in sorted(by_type.items(), key=lambda x: -x[1])[:6]:
                    w(f"    {cnt:<4}  {t}", "value")

            if top_ips:
                w("\n  TOP ATTACKING IPs", "header")
                for ip, cnt in sorted(top_ips.items(), key=lambda x: -x[1])[:5]:
                    w(f"    {cnt:<4}  {ip}", "high")

            if top_usr:
                w("\n  AFFECTED USERS", "header")
                for u, cnt in sorted(top_usr.items(), key=lambda x: -x[1])[:5]:
                    w(f"    {cnt:<4}  {u}", "value")

            w(f"\n{'═'*55}", "header")
            out.config(state="disabled")

        except Exception as e:
            self._set_status(f"Postmortem error: {e}")

    # ── Incident Actions ──────────────────────────────────────────────────────

    def _get_selected_inc_id(self, tree=None):
        tree = tree or self._inc_tree
        sel  = tree.selection()
        if not sel: return None
        vals = tree.item(sel[0])["values"]
        if not vals: return None
        try: return int(str(vals[0]).replace("#",""))
        except Exception: return None

    def _on_incident_dbl(self, event):
        inc_id = self._get_selected_inc_id(self._inc_tree)
        if inc_id: self.show_incident_detail(inc_id)

    def show_incident_detail(self, inc_id: int):
        inc = db.get_incident(inc_id)
        if not inc:
            messagebox.showerror("Not Found", f"Incident #{inc_id} not found.")
            return

        win = tk.Toplevel(self)
        win.title(f"Incident #{inc_id} Details")
        win.configure(bg=C["bg"])
        win.geometry("560x500")
        win.attributes("-topmost", True)

        sev   = (inc.get("severity") or "").lower()
        color = sev_color(sev)

        hdr = tk.Frame(win, bg=color, pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text=f"  #{inc_id} — {inc.get('threat_type','')}",
                 bg=color, fg=C["bg"], font=("Courier New", 11, "bold")).pack(side="left", padx=12)
        SeverityBadge(hdr, sev).pack(side="right", padx=12)

        body = tk.Frame(win, bg=C["bg"], padx=20, pady=14)
        body.pack(fill="both", expand=True)

        def row(k, v, vc=C["text"]):
            f = tk.Frame(body, bg=C["bg"])
            f.pack(fill="x", pady=3)
            tk.Label(f, text=f"{k}:", bg=C["bg"], fg=C["subtext"],
                     font=("Courier New", 9), width=16, anchor="w").pack(side="left")
            tk.Label(f, text=str(v or "—"), bg=C["bg"], fg=vc,
                     font=("Courier New", 9), anchor="w",
                     wraplength=380, justify="left").pack(side="left", fill="x")

        row("Threat Type",   inc.get("threat_type",""),   color)
        row("Severity",      sev.upper(),                 color)
        row("Status",        inc.get("status",""),        C["green"])
        row("Description",   inc.get("description",""),   C["text"])
        row("Source IP",     inc.get("source_ip",""),     C["orange"])
        row("Affected User", inc.get("affected_user",""), C["yellow"])
        row("Detected At",   fmt_time(inc.get("detected_at","")))
        row("Notes",         inc.get("notes",""))

        tk.Frame(body, bg=C["border"], height=1).pack(fill="x", pady=8)

        audits = db.query_audit(inc_id, limit=10)
        if audits:
            tk.Label(body, text="Audit Trail:", bg=C["bg"], fg=C["accent"],
                     font=("Courier New", 9, "bold")).pack(anchor="w")
            for a in audits:
                ok  = "✓" if a.get("success") else "✗"
                clr = C["green"] if a.get("success") else C["red"]
                tk.Label(body,
                    text=f"  {ok} [{fmt_time(a.get('executed_at',''))}] "
                         f"{a.get('action_type','')} — {(a.get('command','') or '')[:40]}",
                    bg=C["bg"], fg=clr, font=("Courier New", 8)
                ).pack(anchor="w")

        btn_row = tk.Frame(win, bg=C["bg"], padx=20, pady=10)
        btn_row.pack(fill="x")
        StyledButton(btn_row, "Respond",
            command=lambda: [win.destroy(), self.open_respond_dialog(inc_id)],
            style="danger").pack(side="left", padx=(0,8))
        StyledButton(btn_row, "Close", command=win.destroy, style="ghost").pack(side="right")

    def _view_selected_incident(self):
        inc_id = self._get_selected_inc_id()
        if inc_id: self.show_incident_detail(inc_id)
        else: messagebox.showwarning("Select Incident", "Please select an incident first.")

    def _respond_selected(self):
        inc_id = self._get_selected_inc_id()
        if inc_id: self.open_respond_dialog(inc_id)
        else: messagebox.showwarning("Select Incident", "Please select an incident first.")

    def open_respond_dialog(self, inc_id: int):
        RespondDialog(self, inc_id)

    def _resolve_selected(self):
        inc_id = self._get_selected_inc_id()
        if not inc_id:
            messagebox.showwarning("Select Incident", "Please select an incident first.")
            return
        if messagebox.askyesno("Resolve", f"Mark Incident #{inc_id} as resolved?"):
            db.update_incident(inc_id, "resolved", "Resolved via GUI")
            db.insert_audit({
                "incident_id": inc_id,
                "action_type": "resolve",
                "command":     "gui_resolve",
                "result":      "Resolved by operator",
                "approved_by": "operator",
                "success":     1,
            })
            self._refresh_incidents()
            self._set_status(f"Incident #{inc_id} resolved.")

    # ── Respond Page ──────────────────────────────────────────────────────────

    def _load_respond_incident(self):
        try:
            inc_id = int(self._respond_inc_var.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Enter a valid incident ID.")
            return
        inc = db.get_incident(inc_id)
        if not inc:
            messagebox.showerror("Not Found", f"Incident #{inc_id} not found.")
            return

        self._current_respond_inc = inc_id
        color = sev_color(inc.get("severity",""))
        self._respond_detail.config(
            text=f"  #{inc_id}  [{(inc.get('severity','') or '').upper()}]  "
                 f"{inc.get('threat_type','')}  —  {(inc.get('description','') or '')[:60]}",
            fg=color
        )

        for w in self._suggest_frame.winfo_children():
            w.destroy()

        for i, action in enumerate(suggest_actions(inc)):
            cmd = action.split(":", 1)[1].strip() if ":" in action else action
            f   = tk.Frame(self._suggest_frame, bg=C["bg3"],
                           highlightbackground=C["border"], highlightthickness=1)
            f.pack(fill="x", pady=2)
            tk.Label(f, text=f" {i+1}.", bg=C["bg3"], fg=C["subtext"],
                     font=("Courier New", 9), width=3).pack(side="left")
            tk.Label(f, text=action[:70], bg=C["bg3"], fg=C["text"],
                     font=("Courier New", 9), anchor="w").pack(side="left", fill="x", expand=True, padx=4)
            StyledButton(f, "Execute",
                command=lambda c=cmd: self._respond_page_execute(c),
                style="danger").pack(side="right", padx=6, pady=3)

    def _respond_page_execute(self, cmd):
        if not self._current_respond_inc:
            messagebox.showwarning("No Incident", "Load an incident first.")
            return
        if not messagebox.askyesno("Confirm", f"Execute?\n\n{cmd}"):
            return
        self._respond_log(f"$ {cmd}")
        try:
            proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=30)
            out  = (proc.stdout + proc.stderr).strip()
            self._respond_log(out or "(no output)")
            db.insert_audit({
                "incident_id": self._current_respond_inc,
                "action_type": "execute",
                "command":     cmd,
                "result":      out[:2000],
                "approved_by": "operator",
                "success":     1 if proc.returncode == 0 else 0,
            })
        except Exception as e:
            self._respond_log(f"Error: {e}")

    def _run_custom_cmd(self):
        cmd = self._custom_cmd_var.get().strip()
        if not cmd: return
        if not is_safe_cmd(cmd):
            messagebox.showerror("Blocked", f"Not in safe command list:\n{cmd}")
            return
        if not messagebox.askyesno("Confirm", f"Execute?\n\n{cmd}"):
            return
        self._respond_page_execute(cmd)

    def _respond_log(self, text):
        self._respond_output.config(state="normal")
        self._respond_output.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
        self._respond_output.see("end")
        self._respond_output.config(state="disabled")

    # ── Live Feed ─────────────────────────────────────────────────────────────

    def _feed_log(self, log: dict):
        msg  = (log.get("message","") or "")[:80]
        lt   = log.get("log_type","")
        proc = (log.get("process","") or "")[:12]
        ts   = datetime.now().strftime("%H:%M:%S")
        tag  = "auth" if lt == "auth" else "info"
        if any(w in msg.lower() for w in ["error","fail","invalid","denied"]):
            tag = "error"
        elif any(w in msg.lower() for w in ["warn","critical"]):
            tag = "warn"

        self._live_feed.config(state="normal")
        self._live_feed.insert("end", f"[{ts}] {proc:<12} {msg}\n", tag)
        lines = int(self._live_feed.index("end-1c").split(".")[0])
        if lines > 200:
            self._live_feed.delete("1.0", "3.0")
        self._live_feed.see("end")
        self._live_feed.config(state="disabled")

    # ── Alert Queue ───────────────────────────────────────────────────────────

    def _show_alert_popup(self, incident: dict):
        with self._alert_lock:
            self._alert_queue.append(incident)

    def _process_alert_queue(self):
        with self._alert_lock:
            while self._alert_queue:
                inc = self._alert_queue.pop(0)
                AlertPopup(self, inc)

    # ── Daemon ────────────────────────────────────────────────────────────────

    def _start_daemon(self):
        if not DB_AVAILABLE:
            self._set_status("Running in demo mode (insightlog package not installed)")
            self._daemon_dot.config(text="⬤  DEMO MODE", fg=C["yellow"])
            return

        def on_new_log(log_dict, log_id):
            self.after(0, lambda: self._feed_log(log_dict))
            evaluate(log_dict, log_id, on_threat=self._on_threat_detected)

        try:
            t1 = LogTailer("syslog", on_new_log=on_new_log)
            t2 = LogTailer("auth",   on_new_log=on_new_log)
            t1.start()
            t2.start()
            self._tailers = [t1, t2]
            self._set_status("Daemon running — watching syslog + auth.log")
        except Exception as e:
            self._set_status(f"Daemon error: {e}")
            self._daemon_dot.config(text="⬤  ERROR", fg=C["red"])

    def _on_threat_detected(self, incident: dict):
        self._show_alert_popup(incident)
        self.after(0, self._refresh_dashboard)
        try:
            handle_new_incident(incident)
        except Exception:
            pass

    def _refresh_loop(self):
        try:
            self._process_alert_queue()
            if self._current_page == "dashboard":
                self._refresh_dashboard()
        except Exception:
            pass
        self.after(5000, self._refresh_loop)

    def _update_clock(self):
        self._clock_var.set(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._update_clock)

    def _set_status(self, msg: str):
        self._status_var.set(f"  {msg}")

    def on_close(self):
        for t in self._tailers:
            try: t.stop()
            except Exception: pass
        self.destroy()


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    app = InsightLogApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()