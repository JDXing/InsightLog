"""
InsightLog - Systemd-compatible Daemon
No double-fork needed — systemd manages the process lifecycle.
"""
import signal
import time
import sys

from insightlog import db_manager as db
from insightlog.log_ingestor import LogTailer
from insightlog.threat_engine import evaluate
from insightlog.incident_manager import handle_new_incident


def _on_new_log(log_dict, log_id):
    evaluate(log_dict, log_id, on_threat=handle_new_incident)


def main():
    print("[Daemon] InsightLog starting...", flush=True)
    db.init_all()

    tailers = [
        LogTailer("syslog", on_new_log=_on_new_log),
        LogTailer("auth",   on_new_log=_on_new_log),
    ]
    for t in tailers:
        t.start()

    print("[Daemon] Watching syslog + auth.log", flush=True)

    def _shutdown(sig, frame):
        print("[Daemon] Shutting down...", flush=True)
        for t in tailers:
            t.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()