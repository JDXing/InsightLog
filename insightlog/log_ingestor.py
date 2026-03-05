"""
InsightLog - Log Ingester and Parser
Ingests /var/log/syslog and /var/log/auth.log
Parses using regex into structured format and stores in D1
"""
import re
import os
import time
import threading
from datetime import datetime
from typing import Optional, Dict, List

from insightlog import db_manager as db

SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>[^\[:]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)$'
)

EVENT_PATTERNS = {
    "ssh_failed":    re.compile(
        r'Failed (?:password|publickey) for (?:invalid user )?'
        r'(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
    ),
    "ssh_success":   re.compile(
        r'Accepted (?:password|publickey) for (?P<user>\S+) '
        r'from (?P<ip>[\d.]+) port (?P<port>\d+)'
    ),
    "sudo_cmd":      re.compile(
        r'(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)$'
    ),
    "su_failed":     re.compile(
        r'(?:FAILED su|authentication failure).*user=(?P<user>\S+)'
    ),
    "new_user":      re.compile(r'new user: name=(?P<user>\S+)'),
    "passwd_change": re.compile(r'password changed for (?P<user>\S+)'),
    "session_open":  re.compile(r'session opened for user (?P<user>\S+)'),
    "session_close": re.compile(r'session closed for user (?P<user>\S+)'),
    "invalid_user":  re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)'),
    "cron_cmd":      re.compile(r'\((?P<user>\S+)\) CMD \((?P<command>.+)\)'),
    "kernel_panic":  re.compile(r'kernel:.*(?:BUG|panic|Oops|segfault|oom-kill)'),
    "disk_error":    re.compile(r'(?:I/O error|EXT\d-fs error|disk failure)'),
    "port_scan":     re.compile(r'(?:nmap|masscan|SYN flood|port scan)'),
    "root_login":    re.compile(r'session opened for user root'),
    "repeated_fail": re.compile(r'FAILED LOGIN \(3\)'),
}

LOG_FILES = {
    "syslog": ["/var/log/syslog", "/var/log/messages"],
    "auth":   ["/var/log/auth.log", "/var/log/secure"],
}


def find_log(log_type: str) -> Optional[str]:
    for p in LOG_FILES.get(log_type, []):
        if os.path.exists(p):
            return p
    return None


def parse_line(line: str, source: str) -> Optional[Dict]:
    line = line.strip()
    if not line:
        return None
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    try:
        ts = datetime.strptime(
            f"{datetime.now().year} {g['month']} {g['day']} {g['time']}",
            "%Y %b %d %H:%M:%S"
        ).isoformat()
    except ValueError:
        ts = datetime.now().isoformat()

    msg = g.get("message", "")
    extra = {}
    for name, pat in EVENT_PATTERNS.items():
        em = pat.search(msg)
        if em:
            extra["event_type"] = name
            try:
                extra.update(em.groupdict())
            except Exception:
                pass
            break

    return {
        "timestamp":   ts,
        "source_file": source,
        "log_type":    "auth" if any(
            x in source for x in ["auth", "secure"]
        ) else "syslog",
        "raw_line":    line,
        "host":        g.get("host", ""),
        "process":     g.get("process", "").strip(),
        "pid":         g.get("pid", ""),
        "message":     msg,
        "parsed_data": extra,
    }


def ingest_once(log_type: str) -> int:
    path = find_log(log_type)
    if not path:
        print(f"[Ingest] No {log_type} log found.")
        return 0
    count = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            parsed = parse_line(line, path)
            if parsed:
                db.insert_log(parsed)
                count += 1
    print(f"[Ingest] {log_type}: {count} entries stored in D1.")
    return count


class LogTailer(threading.Thread):
    """Tails a log file; pushes new entries to D1 and fires on_new_log(log, id)."""

    def __init__(self, log_type: str, on_new_log=None):
        super().__init__(daemon=True, name=f"tail-{log_type}")
        self.log_type   = log_type
        self.on_new_log = on_new_log
        self._stop      = threading.Event()

    def run(self):
        path = find_log(self.log_type)
        if not path:
            print(f"[Tailer] {self.log_type}: file not found.")
            return
        print(f"[Tailer] Watching {path}")
        with open(path, "r", errors="replace") as f:
            f.seek(0, 2)
            while not self._stop.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                parsed = parse_line(line, path)
                if parsed:
                    log_id = db.insert_log(parsed)
                    if self.on_new_log:
                        self.on_new_log(parsed, log_id)

    def stop(self):
        self._stop.set()