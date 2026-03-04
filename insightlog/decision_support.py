"""
Decision Support Interface — Terminal Chatbot
Queries D1 and D2, suggests actions, supports postmortem analysis
"""
import json
import re
from datetime import datetime, timedelta
import db_manager as db
from threat_engine import suggest_actions
from response_executor import interactive_execute

BANNER = """
╔══════════════════════════════════════════════════════════╗
║          InsightLog — Decision Support Interface          ║
║      Type 'help' for commands, 'exit' to quit            ║
╚══════════════════════════════════════════════════════════╝
"""

HELP_TEXT = """
Available commands:
  incidents              — List open incidents
  incidents all          — List all incidents (any status)
  incident <id>          — Show details of a specific incident
  suggest <id>           — Show remediation suggestions for incident
  respond <id>           — Execute remediation for incident (human-in-loop)
  resolve <id>           — Mark incident as resolved
  logs [keyword]         — Show recent logs (optional keyword filter)
  logs auth              — Show recent auth logs
  logs syslog            — Show recent syslog entries
  stats                  — Show log and incident statistics
  postmortem [days]      — Postmortem analysis of past N days (default 7)
  audit [incident_id]    — Show execution audit trail
  search <term>          — Search logs by keyword
  help                   — Show this help
  exit                   — Exit the interface
"""


def fmt_time(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ts or "—"


def show_incidents(rows: list):
    if not rows:
        print("  No incidents found.")
        return
    print(f"\n  {'ID':<5} {'Severity':<10} {'Type':<28} {'Status':<12} {'Detected'}")
    print("  " + "─" * 75)
    for r in rows:
        sev = r['severity'].upper()
        color = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m"}.get(sev, "")
        reset = "\033[0m" if color else ""
        print(f"  {r['id']:<5} {color}{sev:<10}{reset} {r['threat_type']:<28} "
              f"{r['status']:<12} {fmt_time(r['detected_at'])}")
    print()


def postmortem_analysis(days: int = 7):
    since = (datetime.now() - timedelta(days=days)).isoformat()
    incidents = db.query_incidents({"since": since}, limit=500)
    logs      = db.query_logs({"since": since}, limit=1000)

    print(f"\n{'═'*60}")
    print(f"  POSTMORTEM ANALYSIS — Last {days} days")
    print(f"  Period: {fmt_time(since)} → now")
    print(f"{'═'*60}")

    total = len(incidents)
    open_ = sum(1 for i in incidents if i["status"] == "open")
    res   = sum(1 for i in incidents if i["status"] in ("resolved", "mitigated"))

    by_sev = {}
    by_type = {}
    top_ips = {}
    top_users = {}

    for inc in incidents:
        by_sev[inc["severity"]]  = by_sev.get(inc["severity"], 0) + 1
        by_type[inc["threat_type"]] = by_type.get(inc["threat_type"], 0) + 1
        if inc.get("source_ip"):
            top_ips[inc["source_ip"]] = top_ips.get(inc["source_ip"], 0) + 1
        if inc.get("affected_user"):
            top_users[inc["affected_user"]] = top_users.get(inc["affected_user"], 0) + 1

    print(f"\n  Incidents     : {total} total | {open_} open | {res} resolved")
    print(f"  Log entries   : {len(logs)}")
    print(f"\n  By Severity:")
    for sev, cnt in sorted(by_sev.items()):
        print(f"    {sev:<12}: {cnt}")
    print(f"\n  Top Threat Types:")
    for t, cnt in sorted(by_type.items(), key=lambda x: -x[1])[:5]:
        print(f"    {cnt:<4} {t}")
    if top_ips:
        print(f"\n  Top Attacking IPs:")
        for ip, cnt in sorted(top_ips.items(), key=lambda x: -x[1])[:5]:
            print(f"    {cnt:<4} {ip}")
    if top_users:
        print(f"\n  Affected Users:")
        for u, cnt in sorted(top_users.items(), key=lambda x: -x[1])[:5]:
            print(f"    {cnt:<4} {u}")
    print(f"\n{'═'*60}\n")


def run_chat(incident_id: int = None):
    """Launch the interactive Decision Support chatbot."""
    print(BANNER)
    if incident_id:
        inc = db.get_incident(incident_id)
        if inc:
            print(f"  Context: Incident #{incident_id} — {inc['threat_type']} [{inc['severity']}]")
            print(f"  {inc['description']}\n")
            show_incidents([inc])

    while True:
        try:
            user_input = input("insightlog> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting Decision Support Interface.")
            break

        if not user_input:
            continue

        cmd = user_input.lower().split()

        if cmd[0] in ("exit", "quit", "q"):
            print("Goodbye.")
            break

        elif cmd[0] == "help":
            print(HELP_TEXT)

        elif cmd[0] == "incidents":
            all_mode = len(cmd) > 1 and cmd[1] == "all"
            rows = db.query_incidents({} if all_mode else {"status": "open"}, limit=30)
            show_incidents(rows)

        elif cmd[0] == "incident" and len(cmd) > 1:
            try:
                iid = int(cmd[1])
                inc = db.get_incident(iid)
                if inc:
                    print(f"\n{'─'*50}")
                    for k, v in inc.items():
                        if v:
                            print(f"  {k:<16}: {v}")
                    print(f"{'─'*50}\n")
                    audits = db.query_audit(iid)
                    if audits:
                        print(f"  Audit trail ({len(audits)} actions):")
                        for a in audits:
                            print(f"    [{fmt_time(a['executed_at'])}] {a['action_type']} — {a['command']}")
                else:
                    print(f"  Incident #{iid} not found.")
            except ValueError:
                print("  Usage: incident <id>")

        elif cmd[0] == "suggest" and len(cmd) > 1:
            try:
                iid = int(cmd[1])
                sugg = db.get_incident(iid)
                if sugg:
                    actions = suggest_actions(sugg)
                    print(f"\n  Suggested actions for Incident #{iid}:")
                    for i, a in enumerate(actions, 1):
                        print(f"    {i}. {a}")
                    print()
                else:
                    print("  Incident not found.")
            except ValueError:
                print("  Usage: suggest <id>")

        elif cmd[0] == "respond" and len(cmd) > 1:
            try:
                iid = int(cmd[1])
                inc = db.get_incident(iid)
                if inc:
                    actions = suggest_actions(inc)
                    interactive_execute(iid, actions)
                    db.update_incident(iid, "mitigated", "Response executed via DSI.")
                else:
                    print("  Incident not found.")
            except ValueError:
                print("  Usage: respond <id>")

        elif cmd[0] == "resolve" and len(cmd) > 1:
            try:
                iid = int(cmd[1])
                notes = " ".join(cmd[2:]) if len(cmd) > 2 else ""
                db.update_incident(iid, "resolved", notes)
                db.insert_audit({
                    "incident_id": iid,
                    "action_type": "resolve",
                    "command":     "manual",
                    "result":      notes or "Resolved via DSI",
                    "approved_by": "operator",
                    "success":     1,
                })
                print(f"  Incident #{iid} marked as resolved.")
            except ValueError:
                print("  Usage: resolve <id> [notes]")

        elif cmd[0] == "logs":
            filters = {}
            if len(cmd) > 1:
                if cmd[1] in ("auth", "syslog"):
                    filters["log_type"] = cmd[1]
                else:
                    filters["keyword"] = cmd[1]
            rows = db.query_logs(filters, limit=20)
            if rows:
                print(f"\n  {'Time':<18} {'Type':<7} {'Process':<18} Message")
                print("  " + "─" * 80)
                for r in rows:
                    msg = r['message'][:55] if r['message'] else ""
                    print(f"  {fmt_time(r['timestamp']):<18} {r['log_type']:<7} "
                          f"{(r['process'] or '')[:17]:<18} {msg}")
                print()
            else:
                print("  No logs found.")

        elif cmd[0] == "stats":
            ls = db.get_log_stats()
            incs = db.query_incidents(limit=1000)
            open_ = sum(1 for i in incs if i["status"] == "open")
            print(f"\n  Log Stats : {ls['total']} total entries")
            for t, c in ls.get("by_type", {}).items():
                print(f"    {t}: {c}")
            print(f"\n  Incidents : {len(incs)} total | {open_} open")
            print()

        elif cmd[0] == "postmortem":
            days = int(cmd[1]) if len(cmd) > 1 and cmd[1].isdigit() else 7
            postmortem_analysis(days)

        elif cmd[0] == "audit":
            iid = int(cmd[1]) if len(cmd) > 1 and cmd[1].isdigit() else None
            rows = db.query_audit(iid, limit=20)
            if rows:
                print(f"\n  {'Time':<18} {'Inc':<5} {'Type':<20} {'OK':<4} Command")
                print("  " + "─" * 80)
                for r in rows:
                    ok = "✓" if r['success'] else "✗"
                    print(f"  {fmt_time(r['executed_at']):<18} #{r['incident_id'] or '-':<4} "
                          f"{r['action_type']:<20} {ok:<4} {(r['command'] or '')[:35]}")
                print()
            else:
                print("  No audit records found.")

        elif cmd[0] == "search" and len(cmd) > 1:
            term = " ".join(cmd[1:])
            rows = db.query_logs({"keyword": term}, limit=25)
            print(f"\n  Search results for '{term}': {len(rows)} matches")
            for r in rows:
                print(f"  [{fmt_time(r['timestamp'])}] {r['message'][:80]}")
            print()

        else:
            print(f"  Unknown command: '{user_input}'. Type 'help' for options.")