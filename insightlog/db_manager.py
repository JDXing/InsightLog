"""
D1 = Log Database
D2 = Incident Database  
D3 = Audit/Execution Database
"""
import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path

DB_DIR = Path("/var/lib/insightlog")


def _conn(db_name: str) -> sqlite3.Connection:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_DIR / f"{db_name}.db"), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


# ── D1: Logs ──────────────────────────────────────────────────────────────
def init_d1():
    c = _conn("d1_logs")
    c.executescript("""
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            source_file TEXT,
            log_type    TEXT,
            raw_line    TEXT,
            host        TEXT,
            process     TEXT,
            pid         TEXT,
            message     TEXT,
            parsed_data TEXT,
            ingested_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_l_ts   ON logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_l_type ON logs(log_type);
    """)
    c.commit(); c.close()


def insert_log(log: dict) -> int:
    c = _conn("d1_logs")
    cur = c.execute("""
        INSERT INTO logs(timestamp,source_file,log_type,raw_line,host,process,pid,message,parsed_data)
        VALUES(:timestamp,:source_file,:log_type,:raw_line,:host,:process,:pid,:message,:parsed_data)
    """, {**log, "parsed_data": json.dumps(log.get("parsed_data", {}))})
    c.commit(); row_id = cur.lastrowid; c.close()
    return row_id


def query_logs(filters: dict = None, limit: int = 100) -> list:
    c = _conn("d1_logs")
    q, params, clauses = "SELECT * FROM logs", [], []
    if filters:
        if "log_type" in filters: clauses.append("log_type=?"); params.append(filters["log_type"])
        if "since"    in filters: clauses.append("timestamp>=?"); params.append(filters["since"])
        if "keyword"  in filters: clauses.append("message LIKE ?"); params.append(f"%{filters['keyword']}%")
        if "process"  in filters: clauses.append("process LIKE ?"); params.append(f"%{filters['process']}%")
    if clauses: q += " WHERE " + " AND ".join(clauses)
    q += f" ORDER BY timestamp DESC LIMIT {limit}"
    rows = c.execute(q, params).fetchall(); c.close()
    return [dict(r) for r in rows]


def get_log_stats() -> dict:
    c = _conn("d1_logs")
    total = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    by_type = dict(c.execute("SELECT log_type, COUNT(*) FROM logs GROUP BY log_type").fetchall())
    c.close()
    return {"total": total, "by_type": by_type}


# ── D2: Incidents ─────────────────────────────────────────────────────────
def init_d2():
    c = _conn("d2_incidents")
    c.executescript("""
        CREATE TABLE IF NOT EXISTS incidents (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id        INTEGER,
            threat_type   TEXT NOT NULL,
            severity      TEXT NOT NULL,
            description   TEXT NOT NULL,
            source_ip     TEXT,
            affected_user TEXT,
            raw_log       TEXT,
            status        TEXT DEFAULT 'open',
            detected_at   TEXT DEFAULT (datetime('now')),
            resolved_at   TEXT,
            notes         TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_i_status ON incidents(status);
        CREATE INDEX IF NOT EXISTS idx_i_sev    ON incidents(severity);
    """)
    c.commit(); c.close()


def insert_incident(inc: dict) -> int:
    c = _conn("d2_incidents")
    cur = c.execute("""
        INSERT INTO incidents(log_id,threat_type,severity,description,
                              source_ip,affected_user,raw_log,status)
        VALUES(:log_id,:threat_type,:severity,:description,
               :source_ip,:affected_user,:raw_log,:status)
    """, inc)
    c.commit(); inc_id = cur.lastrowid; c.close()
    return inc_id


def query_incidents(filters: dict = None, limit: int = 50) -> list:
    c = _conn("d2_incidents")
    q, params, clauses = "SELECT * FROM incidents", [], []
    if filters:
        if "status"      in filters: clauses.append("status=?"); params.append(filters["status"])
        if "severity"    in filters: clauses.append("severity=?"); params.append(filters["severity"])
        if "threat_type" in filters: clauses.append("threat_type LIKE ?"); params.append(f"%{filters['threat_type']}%")
        if "since"       in filters: clauses.append("detected_at>=?"); params.append(filters["since"])
    if clauses: q += " WHERE " + " AND ".join(clauses)
    q += f" ORDER BY detected_at DESC LIMIT {limit}"
    rows = c.execute(q, params).fetchall(); c.close()
    return [dict(r) for r in rows]


def update_incident(inc_id: int, status: str, notes: str = ""):
    c = _conn("d2_incidents")
    c.execute("""
        UPDATE incidents SET status=?, notes=?,
        resolved_at=CASE WHEN ? IN ('resolved','mitigated') THEN datetime('now') ELSE resolved_at END
        WHERE id=?
    """, (status, notes, status, inc_id))
    c.commit(); c.close()


def get_incident(inc_id: int) -> dict:
    c = _conn("d2_incidents")
    row = c.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
    c.close()
    return dict(row) if row else {}


# ── D3: Audit Log ─────────────────────────────────────────────────────────
def init_d3():
    c = _conn("d3_audit")
    c.executescript("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            action_type TEXT NOT NULL,
            command     TEXT,
            result      TEXT,
            approved_by TEXT DEFAULT 'operator',
            executed_at TEXT DEFAULT (datetime('now')),
            success     INTEGER DEFAULT 1
        );
    """)
    c.commit(); c.close()


def insert_audit(entry: dict) -> int:
    c = _conn("d3_audit")
    cur = c.execute("""
        INSERT INTO audit_log(incident_id,action_type,command,result,approved_by,success)
        VALUES(:incident_id,:action_type,:command,:result,:approved_by,:success)
    """, entry)
    c.commit(); aid = cur.lastrowid; c.close()
    return aid


def query_audit(incident_id: int = None, limit: int = 50) -> list:
    c = _conn("d3_audit")
    if incident_id:
        rows = c.execute("SELECT * FROM audit_log WHERE incident_id=? ORDER BY executed_at DESC LIMIT ?",
                         (incident_id, limit)).fetchall()
    else:
        rows = c.execute("SELECT * FROM audit_log ORDER BY executed_at DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    return [dict(r) for r in rows]


def init_all():
    init_d1(); init_d2(); init_d3()
    print("[DB] All databases initialized.")