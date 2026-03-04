#!/usr/bin/env python3
"""
InsightLog — Main CLI Entry Point
Usage: insightlog <command> [options]
"""
import sys
import os
import argparse


def require_root():
    if os.geteuid() != 0:
        print("[ERROR] This command requires root privileges. Run with sudo.")
        sys.exit(1)


def cmd_start(args):
    require_root()
    from daemon import start_daemon
    start_daemon()


def cmd_stop(args):
    require_root()
    from daemon import stop_daemon
    stop_daemon()


def cmd_status(args):
    from daemon import status_daemon
    status_daemon()


def cmd_foreground(args):
    require_root()
    from daemon import run_foreground
    run_foreground()


def cmd_ingest(args):
    require_root()
    import db_manager as db
    from log_ingestor import ingest_once
    db.init_all()
    if args.type in ("syslog", "all"):
        ingest_once("syslog")
    if args.type in ("auth", "all"):
        ingest_once("auth")


def cmd_incidents(args):
    import db_manager as db
    db.init_all()
    filters = {}
    if args.status:
        filters["status"] = args.status
    rows = db.query_incidents(filters, limit=args.limit)
    from decision_support import show_incidents
    show_incidents(rows)


def cmd_chat(args):
    import db_manager as db
    db.init_all()
    from decision_support import run_chat
    run_chat(incident_id=args.incident)


def cmd_respond(args):
    require_root()
    import db_manager as db
    db.init_all()
    from threat_engine import suggest_actions
    from response_executor import interactive_execute
    inc = db.get_incident(args.incident)
    if not inc:
        print(f"[ERROR] Incident #{args.incident} not found.")
        sys.exit(1)
    print(f"\nIncident #{args.incident}: {inc['threat_type']} [{inc['severity']}]")
    print(f"  {inc['description']}\n")
    actions = suggest_actions(inc)
    interactive_execute(args.incident, actions)
    db.update_incident(args.incident, "mitigated", "Executed via respond command.")


def cmd_postmortem(args):
    import db_manager as db
    db.init_all()
    from decision_support import postmortem_analysis
    postmortem_analysis(args.days)


def cmd_logs(args):
    import db_manager as db
    db.init_all()
    filters = {}
    if args.type:   filters["log_type"] = args.type
    if args.search: filters["keyword"]  = args.search
    rows = db.query_logs(filters, limit=args.limit)
    from decision_support import fmt_time
    if rows:
        print(f"\n  {'Time':<18} {'Type':<7} {'Process':<18} Message")
        print("  " + "─" * 80)
        for r in rows:
            msg = (r['message'] or '')[:55]
            print(f"  {fmt_time(r['timestamp']):<18} {r['log_type']:<7} "
                  f"{(r['process'] or '')[:17]:<18} {msg}")
        print()
    else:
        print("No logs found.")


def cmd_audit(args):
    import db_manager as db
    db.init_all()
    rows = db.query_audit(args.incident, limit=args.limit)
    from decision_support import fmt_time
    print(f"\n  {'Time':<18} {'Inc':<5} {'Type':<20} {'OK'} Command")
    print("  " + "─" * 70)
    for r in rows:
        ok = "✓" if r['success'] else "✗"
        print(f"  {fmt_time(r['executed_at']):<18} #{r['incident_id'] or '-':<4} "
              f"{r['action_type']:<20} {ok}  {(r['command'] or '')[:35]}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="insightlog",
        description="InsightLog — Linux Security Monitoring & Response Tool"
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # start / stop / status / foreground
    sub.add_parser("start",      help="Start background daemon")
    sub.add_parser("stop",       help="Stop background daemon")
    sub.add_parser("status",     help="Show daemon status")
    sub.add_parser("foreground", help="Run in foreground (for testing)")

    # ingest
    p_ing = sub.add_parser("ingest", help="Manually ingest log files into D1")
    p_ing.add_argument("--type", choices=["syslog", "auth", "all"], default="all")

    # incidents
    p_inc = sub.add_parser("incidents", help="List incidents from D2")
    p_inc.add_argument("--status", default="open",
                       choices=["open", "mitigated", "resolved"],
                       help="Filter by status (default: open)")
    p_inc.add_argument("--limit", type=int, default=20)

    # chat (Decision Support Interface)
    p_chat = sub.add_parser("chat", help="Open Decision Support Interface")
    p_chat.add_argument("--incident", type=int, default=None,
                        help="Pre-load context for a specific incident")

    # respond
    p_res = sub.add_parser("respond", help="Execute remediation for an incident")
    p_res.add_argument("--incident", type=int, required=True)

    # postmortem
    p_pm = sub.add_parser("postmortem", help="Postmortem analysis of past N days")
    p_pm.add_argument("--days", type=int, default=7)

    # logs
    p_logs = sub.add_parser("logs", help="Query D1 log database")
    p_logs.add_argument("--type",   choices=["auth", "syslog"], default=None)
    p_logs.add_argument("--search", default=None, help="Keyword search")
    p_logs.add_argument("--limit",  type=int, default=30)

    # audit
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
    main()#!/usr/bin/env python3
"""
InsightLog — Main CLI Entry Point
Usage: insightlog <command> [options]
"""
import sys
import os
import argparse


def require_root():
    if os.geteuid() != 0:
        print("[ERROR] This command requires root privileges. Run with sudo.")
        sys.exit(1)


def cmd_start(args):
    require_root()
    from daemon import start_daemon
    start_daemon()


def cmd_stop(args):
    require_root()
    from daemon import stop_daemon
    stop_daemon()


def cmd_status(args):
    from daemon import status_daemon
    status_daemon()


def cmd_foreground(args):
    require_root()
    from daemon import run_foreground
    run_foreground()


def cmd_ingest(args):
    require_root()
    import db_manager as db
    from log_ingestor import ingest_once
    db.init_all()
    if args.type in ("syslog", "all"):
        ingest_once("syslog")
    if args.type in ("auth", "all"):
        ingest_once("auth")


def cmd_incidents(args):
    import db_manager as db
    db.init_all()
    filters = {}
    if args.status:
        filters["status"] = args.status
    rows = db.query_incidents(filters, limit=args.limit)
    from decision_support import show_incidents
    show_incidents(rows)


def cmd_chat(args):
    import db_manager as db
    db.init_all()
    from decision_support import run_chat
    run_chat(incident_id=args.incident)


def cmd_respond(args):
    require_root()
    import db_manager as db
    db.init_all()
    from threat_engine import suggest_actions
    from response_executor import interactive_execute
    inc = db.get_incident(args.incident)
    if not inc:
        print(f"[ERROR] Incident #{args.incident} not found.")
        sys.exit(1)
    print(f"\nIncident #{args.incident}: {inc['threat_type']} [{inc['severity']}]")
    print(f"  {inc['description']}\n")
    actions = suggest_actions(inc)
    interactive_execute(args.incident, actions)
    db.update_incident(args.incident, "mitigated", "Executed via respond command.")


def cmd_postmortem(args):
    import db_manager as db
    db.init_all()
    from decision_support import postmortem_analysis
    postmortem_analysis(args.days)


def cmd_logs(args):
    import db_manager as db
    db.init_all()
    filters = {}
    if args.type:   filters["log_type"] = args.type
    if args.search: filters["keyword"]  = args.search
    rows = db.query_logs(filters, limit=args.limit)
    from decision_support import fmt_time
    if rows:
        print(f"\n  {'Time':<18} {'Type':<7} {'Process':<18} Message")
        print("  " + "─" * 80)
        for r in rows:
            msg = (r['message'] or '')[:55]
            print(f"  {fmt_time(r['timestamp']):<18} {r['log_type']:<7} "
                  f"{(r['process'] or '')[:17]:<18} {msg}")
        print()
    else:
        print("No logs found.")


def cmd_audit(args):
    import db_manager as db
    db.init_all()
    rows = db.query_audit(args.incident, limit=args.limit)
    from decision_support import fmt_time
    print(f"\n  {'Time':<18} {'Inc':<5} {'Type':<20} {'OK'} Command")
    print("  " + "─" * 70)
    for r in rows:
        ok = "✓" if r['success'] else "✗"
        print(f"  {fmt_time(r['executed_at']):<18} #{r['incident_id'] or '-':<4} "
              f"{r['action_type']:<20} {ok}  {(r['command'] or '')[:35]}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="insightlog",
        description="InsightLog — Linux Security Monitoring & Response Tool"
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # start / stop / status / foreground
    sub.add_parser("start",      help="Start background daemon")
    sub.add_parser("stop",       help="Stop background daemon")
    sub.add_parser("status",     help="Show daemon status")
    sub.add_parser("foreground", help="Run in foreground (for testing)")

    # ingest
    p_ing = sub.add_parser("ingest", help="Manually ingest log files into D1")
    p_ing.add_argument("--type", choices=["syslog", "auth", "all"], default="all")

    # incidents
    p_inc = sub.add_parser("incidents", help="List incidents from D2")
    p_inc.add_argument("--status", default="open",
                       choices=["open", "mitigated", "resolved"],
                       help="Filter by status (default: open)")
    p_inc.add_argument("--limit", type=int, default=20)

    # chat (Decision Support Interface)
    p_chat = sub.add_parser("chat", help="Open Decision Support Interface")
    p_chat.add_argument("--incident", type=int, default=None,
                        help="Pre-load context for a specific incident")

    # respond
    p_res = sub.add_parser("respond", help="Execute remediation for an incident")
    p_res.add_argument("--incident", type=int, required=True)

    # postmortem
    p_pm = sub.add_parser("postmortem", help="Postmortem analysis of past N days")
    p_pm.add_argument("--days", type=int, default=7)

    # logs
    p_logs = sub.add_parser("logs", help="Query D1 log database")
    p_logs.add_argument("--type",   choices=["auth", "syslog"], default=None)
    p_logs.add_argument("--search", default=None, help="Keyword search")
    p_logs.add_argument("--limit",  type=int, default=30)

    # audit
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