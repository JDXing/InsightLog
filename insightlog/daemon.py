"""
InsightLog Background Daemon
Runs log tailing and threat detection continuously
"""
import os
import sys
import signal
import time
import threading
from pathlib import Path

import db_manager as db
from log_ingestor import LogTailer
from threat_engine import evaluate
from incident_manager import handle_new_incident

PID_FILE = "/var/run/insightlog.pid"
LOG_FILE = "/var/log/insightlog_daemon.log"


def _on_new_log(log_dict, log_id):
    """Callback: new log -> threat evaluation -> incident if needed."""
    evaluate(log_dict, log_id, on_threat=handle_new_incident)


def start_daemon():
    """Fork and run as background daemon."""
    # Double-fork
    pid = os.fork()
    if pid > 0:
        print(f"[Daemon] InsightLog started (PID {pid})")
        return

    os.setsid()
    pid2 = os.fork()
    if pid2 > 0:
        sys.exit(0)

    # Redirect stdio
    sys.stdout.flush()
    sys.stderr.flush()
    with open(LOG_FILE, "a") as lf:
        os.dup2(lf.fileno(), sys.stdout.fileno())
        os.dup2(lf.fileno(), sys.stderr.fileno())
    with open(os.devnull) as dn:
        os.dup2(dn.fileno(), sys.stdin.fileno())

    # Write PID
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    print(f"[Daemon] Running (PID {os.getpid()})")

    db.init_all()

    tailers = [
        LogTailer("syslog", on_new_log=_on_new_log),
        LogTailer("auth",   on_new_log=_on_new_log),
    ]
    for t in tailers:
        t.start()

    def _shutdown(sig, frame):
        print("[Daemon] Shutting down...")
        for t in tailers: t.stop()
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    while True:
        time.sleep(1)


def stop_daemon():
    if not os.path.exists(PID_FILE):
        print("[Daemon] Not running.")
        return
    with open(PID_FILE) as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"[Daemon] Stopped (PID {pid})")
    except ProcessLookupError:
        print("[Daemon] Process not found (already stopped?)")
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)


def status_daemon():
    if not os.path.exists(PID_FILE):
        print("[Daemon] Status: NOT RUNNING")
        return
    with open(PID_FILE) as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, 0)
        print(f"[Daemon] Status: RUNNING (PID {pid})")
    except ProcessLookupError:
        print("[Daemon] Status: STALE PID FILE — daemon is not running")


def run_foreground():
    """Run without forking — for testing/debugging."""
    print("[Daemon] Running in foreground (Ctrl+C to stop)")
    db.init_all()
    tailers = [
        LogTailer("syslog", on_new_log=_on_new_log),
        LogTailer("auth",   on_new_log=_on_new_log),
    ]
    for t in tailers:
        t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Daemon] Stopping.")
        for t in tailers: t.stop()