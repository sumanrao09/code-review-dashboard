import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.models import Finding, Metrics

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_path TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    tool_status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    tool TEXT, severity TEXT, rule_id TEXT, title TEXT, description TEXT,
    file TEXT, line INTEGER, cwe TEXT,
    verdict TEXT, confidence TEXT, verdict_note TEXT,
    impact_text TEXT, recommendation TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS metrics (
    scan_id INTEGER PRIMARY KEY,
    total_lines INTEGER, total_code INTEGER, complexity INTEGER,
    cocomo_months REAL, languages TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY, value TEXT
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    meta TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

_FINDING_COLS = ["tool", "severity", "rule_id", "title", "description", "file",
                 "line", "cwe", "verdict", "confidence", "verdict_note",
                 "impact_text", "recommendation"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db(db_path: Path) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    conn.executescript(_SCHEMA)
    conn.commit()
    conn.close()


def create_scan(conn, project_path: str, tools: list) -> int:
    status = {t: {"status": "pending", "error": None} for t in tools}
    cur = conn.execute(
        "INSERT INTO scans (project_path, started_at, tool_status) VALUES (?,?,?)",
        (project_path, _now(), json.dumps(status)),
    )
    conn.commit()
    return cur.lastrowid


def set_tool_status(conn, scan_id: int, tool: str, status: str,
                    error: str | None = None) -> None:
    row = conn.execute("SELECT tool_status FROM scans WHERE id=?",
                       (scan_id,)).fetchone()
    st = json.loads(row["tool_status"])
    st[tool] = {"status": status, "error": error}
    conn.execute("UPDATE scans SET tool_status=? WHERE id=?",
                 (json.dumps(st), scan_id))
    conn.commit()


def finish_scan(conn, scan_id: int) -> None:
    conn.execute("UPDATE scans SET finished_at=? WHERE id=?", (_now(), scan_id))
    conn.commit()


def insert_findings(conn, scan_id: int, findings: list) -> None:
    for f in findings:
        conn.execute(
            f"INSERT INTO findings (scan_id, {','.join(_FINDING_COLS)}) "
            f"VALUES (?, {','.join('?' * len(_FINDING_COLS))})",
            (scan_id, *[getattr(f, c) for c in _FINDING_COLS]),
        )
    conn.commit()


def insert_metrics(conn, scan_id: int, metrics: Metrics) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO metrics VALUES (?,?,?,?,?,?)",
        (scan_id, metrics.total_lines, metrics.total_code, metrics.complexity,
         metrics.cocomo_months, json.dumps(metrics.languages)),
    )
    conn.commit()


def list_scans(conn) -> list:
    rows = conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def get_scan(conn, scan_id: int):
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(row) if row else None


def _row_to_finding(row) -> Finding:
    return Finding(
        id=row["id"], scan_id=row["scan_id"], tool=row["tool"],
        severity=row["severity"], rule_id=row["rule_id"], title=row["title"],
        description=row["description"], file=row["file"], line=row["line"],
        cwe=row["cwe"], verdict=row["verdict"], confidence=row["confidence"],
        verdict_note=row["verdict_note"], impact_text=row["impact_text"],
        recommendation=row["recommendation"],
    )


def get_finding(conn, finding_id: int):
    row = conn.execute("SELECT * FROM findings WHERE id=?",
                       (finding_id,)).fetchone()
    return _row_to_finding(row) if row else None


def get_findings(conn, scan_id: int) -> list:
    rows = conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY id",
                        (scan_id,)).fetchall()
    return [_row_to_finding(r) for r in rows]


def get_metrics(conn, scan_id: int):
    row = conn.execute("SELECT * FROM metrics WHERE scan_id=?",
                       (scan_id,)).fetchone()
    if not row:
        return None
    return Metrics(total_lines=row["total_lines"], total_code=row["total_code"],
                   complexity=row["complexity"],
                   cocomo_months=row["cocomo_months"],
                   languages=json.loads(row["languages"]))


def update_finding_verdict(conn, finding_id: int, verdict: str,
                           confidence, verdict_note, impact_text,
                           recommendation, cwe) -> None:
    conn.execute(
        "UPDATE findings SET verdict=?, confidence=?, verdict_note=?, "
        "impact_text=?, recommendation=?, cwe=COALESCE(?, cwe) WHERE id=?",
        (verdict, confidence, verdict_note, impact_text, recommendation,
         cwe, finding_id),
    )
    conn.commit()


def get_setting(conn, key: str):
    row = conn.execute("SELECT value FROM settings WHERE key=?",
                       (key,)).fetchone()
    return row["value"] if row else None


def set_setting(conn, key: str, value: str) -> None:
    conn.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, value))
    conn.commit()


def create_report(conn, scan_id: int, path: str, meta_json: str) -> int:
    cur = conn.execute(
        "INSERT INTO reports (scan_id, path, meta, created_at) VALUES (?,?,?,?)",
        (scan_id, path, meta_json, _now()),
    )
    conn.commit()
    return cur.lastrowid


def list_reports(conn, scan_id: int) -> list:
    rows = conn.execute("SELECT * FROM reports WHERE scan_id=? ORDER BY id DESC",
                        (scan_id,)).fetchall()
    return [dict(r) for r in rows]
