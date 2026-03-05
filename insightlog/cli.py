#!/usr/bin/env python3
"""
InsightLog - CLI Entry Point
"""
import sys
import os
import argparse


def require_root():
    if os.geteuid() != 0:
        print("[ERROR] This command requires root. Run with sudo.")
        sys.exit(1)


def cmd_start(args):
    require_root()
    from insightlog.daemon import start_daemon
    start_daemon()


def cmd_stop(args):
    require_root()
    from insightlog.daemon import stop_daemon
    stop_daemon()


def cmd_status(args):
    from insightlog.daemon import status_daemon
    status_daemon()


def cmd_foreground(args):
    require_root()
    from insightlog.daemon import run_foreground
    run_foreground()


def cmd_ingest(args):
    require_root()
    from insightlog import db_manager as db
    from insightlog.log_ingestor import ingest_once
    db.init_all()
    if args.type in ("syslog", "all"):
        ingest_once("syslog")
    if args.type in ("auth", "all"):
        ingest_once("auth")


def cmd_incidents(args):
    from insightlog import db_manager as db
    from insightlog.decision_support import show_incidents
    db.init_all()
    filters = {}
    if args.status:
        filters["status"] = args.status
    rows = db.query_incidents(filters, limit=args.limit)
    show_incidents(rows)


def cmd_chat(args):
    from insightlog import db_manager as db
    from insightlog.decision_support import run_chat
    db.init_all()
    run_chat(incident_id=args.incident)


def cmd_respond(args):
    require_root()
    from insightlog import db_manager as db
    from insightlog.threat_engine import suggest_actions
    from insightlog.response_executor import interactive_execute
    db.init_all()
    inc = db.get_incident(args.incident)
    if not inc:
        print(f"[ERROR] Incident #{args.incident} not found.")
        sys.exit(1)
    print(f"\nIncident #{args.incident}: "
          f"{inc['threat_type']} [{inc['severity']}]")
    print(f"  {inc['description']}\n")
    actions = suggest_actions(inc)
    interactive_execute(args.incident, actions)
    db.update_incident(args.incident, "mitigated",
                       "Executed via respond command.")


def cmd_postmortem(args):
    from insightlog import db_manager as db
    from insightlog.decision_support import postmortem_analysis
    db.init_all()
    postmortem_analysis(args.days)


def cmd_logs(args):
    from insightlog import db_manager as db
    from insightlog.decision_support import fmt_time
    db.init_all()
    filters = {}
    if args.type:   filters["log_type"] = args.type
    if args.search: filters["keyword"]  = args.search
    rows = db.query_logs(filters, limit=args.limit)
    if rows:
        print(f"\n  {'Time':<18} {'Type':<7} {'Process':<18} Message")
        print("  " + "─" * 75)
        for r in rows:
            msg = (r["message"] or "")[:50]
            print(f"  {fmt_time(r['timestamp']):<18} {r['log_type']:<7} "
                  f"{(r['process'] or '')[:17]:<18} {msg}")
        print()
    else:
        print("No logs found.")


def cmd_audit(args):
    from insightlog import db_manager as db
    from insightlog.decision_support import fmt_time
    db.init_all()
    rows = db.query_audit(args.incident, limit=args.limit)
    print(f"\n  {'Time':<18} {'Inc':<5} {'Type':<20} OK  Command")
    print("  " + "─" * 70)
    for r in rows:
        ok = "✓" if r["success"] else "✗"
        print(f"  {fmt_time(r['executed_at']):<18} "
              f"#{r['incident_id'] or '-':<4} "
              f"{r['action_type']:<20} {ok}   "
              f"{(r['command'] or '')[:30]}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="insightlog",
        description="InsightLog — Linux Security Monitoring & Response Tool"
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    sub.add_parser("start",      help="Start background daemon")
    sub.add_parser("stop",       help="Stop background daemon")
    sub.add_parser("status",     help="Show daemon status")
    sub.add_parser("foreground", help="Run in foreground (debug)")

    p_ing = sub.add_parser("ingest", help="Manually ingest logs into D1")
    p_ing.add_argument("--type",
                       choices=["syslog", "auth", "all"], default="all")

    p_inc = sub.add_parser("incidents", help="List incidents from D2")
    p_inc.add_argument("--status", default="open",
                       choices=["open", "mitigated", "resolved"])
    p_inc.add_argument("--limit", type=int, default=20)

    p_chat = sub.add_parser("chat", help="Open Decision Support Interface")
    p_chat.add_argument("--incident", type=int, default=None)

    p_res = sub.add_parser("respond", help="Execute remediation for incident")
    p_res.add_argument("--incident", type=int, required=True)

    p_pm = sub.add_parser("postmortem", help="Postmortem analysis")
    p_pm.add_argument("--days", type=int, default=7)

    p_logs = sub.add_parser("logs", help="Query D1 log database")
    p_logs.add_argument("--type",   choices=["auth", "syslog"], default=None)
    p_logs.add_argument("--search", default=None)
    p_logs.add_argument("--limit",  type=int, default=30)

    p_audit = sub.add_parser("audit", help="Show D3 execution audit trail")
    p_audit.add_argument("--incident", type=int, default=None)
    p_audit.add_argument("--limit",    type=int, default=30)

    args = parser.parse_args()

    dispatch = {
        "start":      cmd_start,
        "stop":       cmd_stop,
        "status":     cmd_status,
        "foreground": cmd_foreground,
        "ingest":     cmd_ingest,
        "incidents":  cmd_incidents,
        "chat":       cmd_chat,
        "respond":    cmd_respond,
        "postmortem": cmd_postmortem,
        "logs":       cmd_logs,
        "audit":      cmd_audit,
    }

    if not args.command:
        parser.print_help()
        sys.exit(0)

    fn = dispatch.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()