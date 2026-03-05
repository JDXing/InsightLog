"""
InsightLog - Background Daemon
"""
import os
import sys
import signal
import time

from insightlog import db_manager as db
from insightlog.log_ingestor import LogTailer
from insightlog.threat_engine import evaluate
from insightlog.incident_manager import handle_new_incident

PID_FILE = "/var/run/insightlog.pid"
LOG_FILE = "/var/log/insightlog_daemon.log"


def _on_new_log(log_dict, log_id):
    evaluate(log_dict, log_id, on_threat=handle_new_incident)


def start_daemon():
    pid = os.fork()
    if pid > 0:
        print(f"[Daemon] InsightLog started (PID {pid})")
        return

    os.setsid()
    pid2 = os.fork()
    if pid2 > 0:
        sys.exit(0)

    sys.stdout.flush()
    sys.stderr.flush()
    with open(LOG_FILE, "a") as lf:
        os.dup2(lf.fileno(), sys.stdout.fileno())
        os.dup2(lf.fileno(), sys.stderr.fileno())
    with open(os.devnull) as dn:
        os.dup2(dn.fileno(), sys.stdin.fileno())

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
        for t in tailers:
            t.stop()
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
        print("[Daemon] Process not found.")
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
        print("[Daemon] Status: STALE PID — daemon not running")
    except PermissionError:
        print(f"[Daemon] Status: RUNNING (PID {pid}) — started as root")


def run_foreground():
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
        for t in tailers:
            t.stop()