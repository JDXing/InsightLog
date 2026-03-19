"""
InsightLog - Log Ingester and Parser
Ingests /var/log/syslog and /var/log/auth.log
Parses using regex into structured format and stores in D1
"""
import re
import os
import time
import threading
import subprocess
from datetime import datetime
from typing import Optional, Dict

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
    "root_login":    re.compile(r'(?:session opened for user root|Accepted (?:password|publickey) for root)'),
    "ssh_success":   re.compile(
        r'Accepted (?:password|publickey) for (?P<user>\S+) '
        r'from (?P<ip>[\d.]+) port (?P<port>\d+)'
    ),
    "sudo_cmd":      re.compile(
        r'(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)$'
    ),
    "su_failed":     re.compile(
        r'(?:FAILED su for \S+ by (?P<user>\S+)|authentication failure.*user=(?P<user2>\S+))'
    ),
    "new_user":      re.compile(r'new user: name=(?P<user>\S+)'),
    "passwd_change": re.compile(r'password changed for (?P<user>\S+)'),
    "session_open":  re.compile(r'session opened for user (?P<user>\S+)'),
    "session_close": re.compile(r'session closed for user (?P<user>\S+)'),
    "invalid_user":  re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)'),
    "cron_cmd":      re.compile(r'\((?P<user>\S+)\) CMD \((?P<command>.+)\)'),
    "kernel_panic":  re.compile(r'(?:kernel:.*)?(?:BUG|[Kk]ernel panic|Oops|segfault|oom-kill|Out of memory)'),
    "disk_error":    re.compile(r'(?:I/O error|EXT\d-fs error|disk failure)'),
    "port_scan":     re.compile(r'(?:nmap|masscan|SYN flood|port scan)'),
    "repeated_fail": re.compile(r'FAILED LOGIN \(3\)'),
}

LOG_FILES = {
    "syslog": [
        "/var/log/syslog",       # Debian/Ubuntu/Kali
        "/var/log/messages",     # RHEL/CentOS/Fedora
        "/var/log/kern.log",     # Kali fallback
        "/var/log/daemon.log",   # Another Kali fallback
    ],
    "auth": [
        "/var/log/auth.log",     # Debian/Ubuntu/Kali
        "/var/log/secure",       # RHEL/CentOS/Fedora
    ],
}

# Cache so we don't re-check every call
_log_path_cache: Dict[str, Optional[str]] = {}


def _ensure_syslog() -> bool:
    """Auto-installs rsyslog on Kali/journald systems where syslog is missing."""
    for p in LOG_FILES["syslog"]:
        if os.path.exists(p):
            return True
    try:
        print("[Ingestor] syslog not found — installing rsyslog automatically...", flush=True)
        result = subprocess.run(
            ["apt-get", "install", "-y", "-q", "rsyslog"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            subprocess.run(["systemctl", "enable", "--now", "rsyslog"],
                           capture_output=True, timeout=10)
            time.sleep(2)
            for p in LOG_FILES["syslog"]:
                if os.path.exists(p):
                    print(f"[Ingestor] rsyslog installed — now watching {p}", flush=True)
                    return True
    except Exception as e:
        print(f"[Ingestor] Could not auto-install rsyslog: {e}", flush=True)
    try:
        syslog_path = "/var/log/syslog"
        print("[Ingestor] Falling back to journald export...", flush=True)
        subprocess.run(
            f"journalctl -o short-traditional --no-pager -n 10000 > {syslog_path}",
            shell=True, capture_output=True, timeout=15
        )
        if os.path.exists(syslog_path) and os.path.getsize(syslog_path) > 0:
            os.chmod(syslog_path, 0o644)
            print(f"[Ingestor] Journald exported to {syslog_path}", flush=True)
            return True
    except Exception as e:
        print(f"[Ingestor] Journald export failed: {e}", flush=True)
    return False


def _ensure_log_readable(path: str) -> bool:
    """Makes a log file readable without requiring manual chmod."""
    if not os.path.exists(path):
        return False
    if os.access(path, os.R_OK):
        return True
    try:
        subprocess.run(["sudo", "chmod", "a+r", path],
                       capture_output=True, timeout=5)
        return os.access(path, os.R_OK)
    except Exception:
        return False


def find_log(log_type: str) -> Optional[str]:
    """Find the best available log file, auto-handling missing syslog."""
    if log_type in _log_path_cache:
        return _log_path_cache[log_type]
    if log_type == "syslog":
        _ensure_syslog()
    for p in LOG_FILES.get(log_type, []):
        if _ensure_log_readable(p):
            _log_path_cache[log_type] = p
            return p
    _log_path_cache[log_type] = None
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

    msg     = g.get("message", "")
    process = g.get("process", "").strip().lower()
    extra   = {}

    # When process field IS "kernel", prepend so patterns fire correctly
    search_text = f"kernel: {msg}" if process == "kernel" else msg

    for name, pat in EVENT_PATTERNS.items():
        em = pat.search(search_text)
        if em:
            extra["event_type"] = name
            try:
                gd = {k: v for k, v in em.groupdict().items() if v is not None}
                # su_failed uses two named groups — normalise user2 -> user
                if "user2" in gd:
                    gd["user"] = gd.pop("user2")
                extra.update(gd)
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
        # Retry up to 10 times — handles rsyslog startup delay
        path = None
        for attempt in range(10):
            _log_path_cache.pop(self.log_type, None)
            path = find_log(self.log_type)
            if path:
                break
            if attempt < 9:
                print(f"[Tailer] {self.log_type}: not available yet, "
                      f"retrying in 3s... ({attempt+1}/10)", flush=True)
                time.sleep(3)
        if not path:
            print(f"[Tailer] {self.log_type}: log file not found after retries. Skipping.", flush=True)
            return
        print(f"[Tailer] Watching {path}", flush=True)
        try:
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
        except Exception as e:
            print(f"[Tailer] {self.log_type}: error reading {path}: {e}", flush=True)

    def stop(self):
        self._stop.set()