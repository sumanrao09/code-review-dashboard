# Secure Code Review Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A local FastAPI web dashboard that runs Semgrep, SonarQube, Snyk, and SCC against a project path in one go, aggregates the results, lets an LLM validate findings as true/false positives, and generates a standalone HTML vulnerability report.

**Architecture:** Python 3 + FastAPI backend serving a vanilla HTML/JS/CSS frontend (no build step). SQLite for scans, findings, metrics, settings, and reports. Each scanner is an independent runner module (`run()` + `parse()`); scans run tools concurrently as subprocesses. AI Validate calls a configurable provider (Anthropic or OpenAI) per finding using structured outputs. Report Generation renders one Jinja2 template adapted from the reference `Vulnerability-Report.HTML`.

**Tech Stack:** Python 3.12, FastAPI, Uvicorn, Jinja2, `anthropic` SDK, `openai` SDK, `httpx`, pytest. SonarQube Community + sonar-scanner via Docker. Semgrep (pip), Snyk CLI (npm), SCC (binary).

## Global Constraints

- Local, single-user only. No authentication, no multi-tenancy. Bind to `127.0.0.1:8000`.
- Code input is a **local filesystem path** only (no git-clone or zip upload).
- A tool/runner failure must **not** abort the scan — mark that tool failed and continue with the rest.
- AI provider API keys are stored only in the local SQLite `settings` table. Never hard-code keys; never log key values.
- AI Validate is **manual** (button-triggered), never automatic on scan completion.
- Report default filter: include `confirmed` + `partially_true` findings; false positives only in an appendix when the checkbox is set.
- Anthropic calls use model `claude-opus-4-8`. On `stop_reason == "refusal"`, opt into a server-side fallback to `claude-opus-4-8` and, if still refused, mark the finding `inconclusive`.
- Normalized severities are exactly: `critical`, `high`, `medium`, `low`, `info`.
- Verdict values are exactly: `confirmed`, `partially_true`, `false_positive`, `inconclusive`.
- All temporary/working files for a scan live under `data/scans/<scan_id>/`. The SQLite DB is `data/app.db`.
- Every code step is TDD: write the failing test, watch it fail, implement, watch it pass, commit.

## File Structure

- `app/config.py` — resolved paths (`DATA_DIR`, `DB_PATH`, `SCANS_DIR`) and defaults.
- `app/models.py` — `Finding`, `Metrics`, `Verdict` dataclasses; severity/verdict constants and mapping helpers.
- `app/db.py` — SQLite schema init and all queries.
- `app/settings.py` — provider/API-key key-value accessors over the `settings` table.
- `app/runners/base.py` — runner registry and the `Runner` protocol.
- `app/runners/semgrep.py`, `scc.py`, `snyk.py`, `sonarqube.py` — one module per tool.
- `app/scanner.py` — orchestration: preflight, parallel runs, timeouts, persistence.
- `app/validator/base.py` — `Provider` protocol + prompt/context builder.
- `app/validator/providers/anthropic.py`, `openai.py` — provider adapters.
- `app/validator/service.py` — per-scan validation orchestration.
- `app/report/generator.py` — findings+verdicts → `DATA` JSON → rendered HTML.
- `app/report/template.html` — Jinja2 template adapted from the reference report.
- `app/main.py` — FastAPI app, API routes, static mount.
- `app/static/index.html`, `app.js`, `style.css` — the single-page UI.
- `tests/` — mirrors `app/` with fixtures under `tests/fixtures/`.

---

### Task 1: Project scaffolding and health endpoint

**Files:**
- Create: `requirements.txt`, `pyproject.toml`, `.gitignore`, `app/__init__.py`, `app/config.py`, `app/main.py`
- Test: `tests/test_health.py`, `tests/__init__.py`

**Interfaces:**
- Produces: `app.main.app` (FastAPI instance); `GET /api/health` → `{"status": "ok"}`; `app.config.DATA_DIR`, `app.config.DB_PATH`, `app.config.SCANS_DIR` (all `pathlib.Path`).

- [ ] **Step 1: Create dependency and config files**

`requirements.txt`:
```
fastapi==0.115.0
uvicorn[standard]==0.30.6
jinja2==3.1.4
httpx==0.27.2
anthropic==0.39.0
openai==1.51.0
pytest==8.3.3
```

`pyproject.toml`:
```toml
[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]
```

`.gitignore`:
```
__pycache__/
*.pyc
.venv/
data/
```

- [ ] **Step 2: Create the config module**

`app/config.py`:
```python
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "app.db"
SCANS_DIR = DATA_DIR / "scans"

TOOL_TIMEOUT_SECONDS = 15 * 60
VALIDATE_CONCURRENCY = 5


def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    SCANS_DIR.mkdir(exist_ok=True)
```

- [ ] **Step 3: Write the failing test**

`tests/__init__.py`: (empty file)

`tests/test_health.py`:
```python
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_returns_ok():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt && pytest tests/test_health.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.main'`.

- [ ] **Step 5: Create the FastAPI app**

`app/__init__.py`: (empty file)

`app/main.py`:
```python
from fastapi import FastAPI

from app.config import ensure_dirs

app = FastAPI(title="Secure Code Review Dashboard")


@app.on_event("startup")
def _startup() -> None:
    ensure_dirs()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_health.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add requirements.txt pyproject.toml .gitignore app/ tests/
git commit -m "feat: project scaffolding and health endpoint"
```

---

### Task 2: Data models and severity mapping

**Files:**
- Create: `app/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces:
  - `Finding` dataclass with fields: `tool, severity, rule_id, title, description, file` (required) and `line=None, cwe=None, verdict=None, confidence=None, verdict_note=None, impact_text=None, recommendation=None, id=None, scan_id=None`.
  - `Metrics` dataclass: `total_lines: int, total_code: int, complexity: int, cocomo_months: float, languages: list[dict]`.
  - `SEVERITIES = ["critical","high","medium","low","info"]`, `VERDICTS = ["confirmed","partially_true","false_positive","inconclusive"]`.
  - `normalize_severity(tool: str, raw: str) -> str`.

- [ ] **Step 1: Write the failing test**

`tests/test_models.py`:
```python
from app.models import Finding, normalize_severity, SEVERITIES


def test_finding_defaults():
    f = Finding(tool="semgrep", severity="high", rule_id="r1",
                title="t", description="d", file="a.py")
    assert f.line is None
    assert f.verdict is None
    assert f.severity in SEVERITIES


def test_normalize_severity_sonarqube():
    assert normalize_severity("sonarqube", "BLOCKER") == "critical"
    assert normalize_severity("sonarqube", "MAJOR") == "medium"


def test_normalize_severity_semgrep():
    assert normalize_severity("semgrep", "ERROR") == "high"
    assert normalize_severity("semgrep", "WARNING") == "medium"


def test_normalize_severity_snyk_passthrough():
    assert normalize_severity("snyk", "critical") == "critical"


def test_normalize_severity_unknown_defaults_to_info():
    assert normalize_severity("semgrep", "SOMETHING") == "info"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.models'`.

- [ ] **Step 3: Implement the models**

`app/models.py`:
```python
from dataclasses import dataclass, field
from typing import Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]
VERDICTS = ["confirmed", "partially_true", "false_positive", "inconclusive"]

_SEVERITY_MAP = {
    "sonarqube": {"BLOCKER": "critical", "CRITICAL": "high", "MAJOR": "medium",
                  "MINOR": "low", "INFO": "info"},
    "semgrep": {"ERROR": "high", "WARNING": "medium", "INFO": "info"},
    "snyk": {"critical": "critical", "high": "high", "medium": "medium",
             "low": "low"},
}


def normalize_severity(tool: str, raw: str) -> str:
    table = _SEVERITY_MAP.get(tool, {})
    return table.get(raw, table.get(str(raw).upper(), "info"))


@dataclass
class Finding:
    tool: str
    severity: str
    rule_id: str
    title: str
    description: str
    file: str
    line: Optional[int] = None
    cwe: Optional[str] = None
    verdict: Optional[str] = None
    confidence: Optional[str] = None
    verdict_note: Optional[str] = None
    impact_text: Optional[str] = None
    recommendation: Optional[str] = None
    id: Optional[int] = None
    scan_id: Optional[int] = None


@dataclass
class Metrics:
    total_lines: int = 0
    total_code: int = 0
    complexity: int = 0
    cocomo_months: float = 0.0
    languages: list = field(default_factory=list)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_models.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add app/models.py tests/test_models.py
git commit -m "feat: normalized finding/metrics models and severity mapping"
```

---

### Task 3: SQLite schema and queries

**Files:**
- Create: `app/db.py`
- Test: `tests/test_db.py`

**Interfaces:**
- Consumes: `Finding`, `Metrics` from `app.models`.
- Produces (all in `app.db`):
  - `init_db(db_path: Path) -> None`
  - `connect(db_path: Path) -> sqlite3.Connection` (row factory = `sqlite3.Row`)
  - `create_scan(conn, project_path: str, tools: list[str]) -> int`
  - `set_tool_status(conn, scan_id: int, tool: str, status: str, error: str | None = None) -> None`
  - `finish_scan(conn, scan_id: int) -> None`
  - `insert_findings(conn, scan_id: int, findings: list[Finding]) -> None`
  - `insert_metrics(conn, scan_id: int, metrics: Metrics) -> None`
  - `list_scans(conn) -> list[dict]`
  - `get_scan(conn, scan_id: int) -> dict | None`
  - `get_findings(conn, scan_id: int) -> list[Finding]`
  - `get_metrics(conn, scan_id: int) -> Metrics | None`
  - `update_finding_verdict(conn, finding_id: int, verdict: str, confidence: str | None, verdict_note: str | None, impact_text: str | None, recommendation: str | None, cwe: str | None) -> None`
  - `get_setting(conn, key: str) -> str | None`, `set_setting(conn, key: str, value: str) -> None`
  - `create_report(conn, scan_id: int, path: str, meta_json: str) -> int`, `list_reports(conn, scan_id: int) -> list[dict]`
- Per-scan tool status is stored as a JSON object on the `scans` row (`tool_status` column: `{"semgrep": {"status": "...", "error": null}}`).

- [ ] **Step 1: Write the failing test**

`tests/test_db.py`:
```python
import json
from app import db
from app.models import Finding, Metrics


def _conn(tmp_path):
    p = tmp_path / "t.db"
    db.init_db(p)
    return db.connect(p)


def test_create_and_get_scan(tmp_path):
    conn = _conn(tmp_path)
    sid = db.create_scan(conn, "/proj", ["semgrep", "scc"])
    scan = db.get_scan(conn, sid)
    assert scan["project_path"] == "/proj"
    assert json.loads(scan["tool_status"])["semgrep"]["status"] == "pending"


def test_tool_status_update(tmp_path):
    conn = _conn(tmp_path)
    sid = db.create_scan(conn, "/proj", ["semgrep"])
    db.set_tool_status(conn, sid, "semgrep", "failed", "boom")
    st = json.loads(db.get_scan(conn, sid)["tool_status"])
    assert st["semgrep"] == {"status": "failed", "error": "boom"}


def test_insert_and_get_findings(tmp_path):
    conn = _conn(tmp_path)
    sid = db.create_scan(conn, "/proj", ["semgrep"])
    db.insert_findings(conn, sid, [
        Finding(tool="semgrep", severity="high", rule_id="r",
                title="t", description="d", file="a.py", line=3),
    ])
    got = db.get_findings(conn, sid)
    assert len(got) == 1
    assert got[0].line == 3
    assert got[0].id is not None


def test_update_verdict(tmp_path):
    conn = _conn(tmp_path)
    sid = db.create_scan(conn, "/proj", ["semgrep"])
    db.insert_findings(conn, sid, [
        Finding(tool="semgrep", severity="high", rule_id="r",
                title="t", description="d", file="a.py"),
    ])
    fid = db.get_findings(conn, sid)[0].id
    db.update_finding_verdict(conn, fid, "confirmed", "high", "note",
                              "impact", "fix", "CWE-89")
    f = db.get_findings(conn, sid)[0]
    assert f.verdict == "confirmed"
    assert f.cwe == "CWE-89"


def test_metrics_roundtrip(tmp_path):
    conn = _conn(tmp_path)
    sid = db.create_scan(conn, "/proj", ["scc"])
    db.insert_metrics(conn, sid, Metrics(total_lines=10, total_code=8,
                      complexity=2, cocomo_months=1.5,
                      languages=[{"Name": "Python", "Code": 8}]))
    m = db.get_metrics(conn, sid)
    assert m.total_code == 8
    assert m.languages[0]["Name"] == "Python"


def test_settings_and_reports(tmp_path):
    conn = _conn(tmp_path)
    db.set_setting(conn, "provider", "anthropic")
    assert db.get_setting(conn, "provider") == "anthropic"
    sid = db.create_scan(conn, "/proj", ["semgrep"])
    rid = db.create_report(conn, sid, "data/scans/1/report.html", "{}")
    assert db.list_reports(conn, sid)[0]["id"] == rid
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_db.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.db'`.

- [ ] **Step 3: Implement db.py**

`app/db.py`:
```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_db.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add app/db.py tests/test_db.py
git commit -m "feat: sqlite schema and queries"
```

---

### Task 4: Runner base + Semgrep runner

**Files:**
- Create: `app/runners/__init__.py`, `app/runners/base.py`, `app/runners/semgrep.py`
- Create: `tests/fixtures/semgrep.json`
- Test: `tests/test_semgrep_runner.py`

**Interfaces:**
- Consumes: `Finding`, `normalize_severity` from `app.models`.
- Produces:
  - `app.runners.base.RUNNERS: dict[str, module]` — name → runner module registry.
  - Runner module contract: `NAME: str`, `BINARY: str`, `run(project_path: str, workdir: Path) -> Path` (writes and returns raw output file), `parse(raw_path: Path) -> list[Finding]`.
  - `app.runners.semgrep` implementing that contract.

- [ ] **Step 1: Create the Semgrep fixture**

`tests/fixtures/semgrep.json`:
```json
{
  "results": [
    {
      "check_id": "python.lang.security.audit.exec-detected",
      "path": "app/vuln.py",
      "start": {"line": 12},
      "extra": {
        "message": "Detected use of exec().",
        "severity": "ERROR",
        "metadata": {"cwe": ["CWE-95: Improper Neutralization of Directives"]}
      }
    },
    {
      "check_id": "python.lang.best-practice.print",
      "path": "app/util.py",
      "start": {"line": 3},
      "extra": {"message": "print used", "severity": "INFO", "metadata": {}}
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

`tests/test_semgrep_runner.py`:
```python
from pathlib import Path
from app.runners import semgrep


def test_parse_semgrep(tmp_path):
    raw = Path("tests/fixtures/semgrep.json")
    findings = semgrep.parse(raw)
    assert len(findings) == 2
    first = findings[0]
    assert first.tool == "semgrep"
    assert first.severity == "high"
    assert first.file == "app/vuln.py"
    assert first.line == 12
    assert first.cwe == "CWE-95"
    assert findings[1].severity == "info"


def test_registry_contains_semgrep():
    from app.runners.base import RUNNERS
    assert "semgrep" in RUNNERS
    assert RUNNERS["semgrep"].NAME == "semgrep"
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_semgrep_runner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.runners'`.

- [ ] **Step 4: Implement base + semgrep**

`app/runners/__init__.py`: (empty file)

`app/runners/semgrep.py`:
```python
import json
import subprocess
from pathlib import Path

from app.models import Finding, normalize_severity

NAME = "semgrep"
BINARY = "semgrep"


def run(project_path: str, workdir: Path) -> Path:
    out = workdir / "semgrep.json"
    proc = subprocess.run(
        [BINARY, "scan", "--config", "auto", "--json", project_path],
        capture_output=True, text=True,
    )
    out.write_text(proc.stdout or "{}")
    return out


def _cwe_id(metadata: dict) -> str | None:
    cwes = metadata.get("cwe") or []
    if not cwes:
        return None
    first = cwes[0] if isinstance(cwes, list) else cwes
    return str(first).split(":")[0].strip()


def parse(raw_path: Path) -> list:
    data = json.loads(Path(raw_path).read_text() or "{}")
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        findings.append(Finding(
            tool=NAME,
            severity=normalize_severity(NAME, extra.get("severity", "INFO")),
            rule_id=r.get("check_id", ""),
            title=r.get("check_id", "").split(".")[-1] or "semgrep finding",
            description=extra.get("message", ""),
            file=r.get("path", ""),
            line=r.get("start", {}).get("line"),
            cwe=_cwe_id(extra.get("metadata", {})),
        ))
    return findings
```

`app/runners/base.py`:
```python
from app.runners import semgrep, scc, snyk, sonarqube

RUNNERS = {m.NAME: m for m in (semgrep, scc, snyk, sonarqube)}
```

> Note: `base.py` imports `scc`, `snyk`, `sonarqube` which are created in Tasks 5–7. To keep this task runnable in isolation, temporarily set `RUNNERS = {semgrep.NAME: semgrep}` and import only `semgrep`; restore the full tuple at the end of Task 7. The Step-2 test only checks that `semgrep` is present, so the temporary form passes.

Temporary `app/runners/base.py` for this task:
```python
from app.runners import semgrep

RUNNERS = {semgrep.NAME: semgrep}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_semgrep_runner.py -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Commit**

```bash
git add app/runners/ tests/test_semgrep_runner.py tests/fixtures/semgrep.json
git commit -m "feat: runner base registry and semgrep runner"
```

---

### Task 5: SCC runner (metrics)

**Files:**
- Create: `app/runners/scc.py`
- Create: `tests/fixtures/scc.json`
- Test: `tests/test_scc_runner.py`

**Interfaces:**
- Consumes: `Metrics` from `app.models`.
- Produces: `app.runners.scc` with `NAME="scc"`, `BINARY="scc"`, `run(project_path, workdir) -> Path`, and `parse_metrics(raw_path: Path) -> Metrics`. (SCC feeds metrics, not findings, so it exposes `parse_metrics` rather than `parse`; the scanner special-cases it.)

- [ ] **Step 1: Create the SCC fixture**

`tests/fixtures/scc.json`:
```json
[
  {"Name": "Python", "Lines": 120, "Code": 90, "Comment": 20, "Blank": 10, "Complexity": 15, "Count": 3},
  {"Name": "JavaScript", "Lines": 60, "Code": 50, "Comment": 5, "Blank": 5, "Complexity": 8, "Count": 2}
]
```

- [ ] **Step 2: Write the failing test**

`tests/test_scc_runner.py`:
```python
from pathlib import Path
from app.runners import scc


def test_parse_scc_metrics():
    m = scc.parse_metrics(Path("tests/fixtures/scc.json"))
    assert m.total_code == 140
    assert m.total_lines == 180
    assert m.complexity == 23
    assert len(m.languages) == 2
    assert m.cocomo_months > 0
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_scc_runner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.runners.scc'`.

- [ ] **Step 4: Implement scc.py**

`app/runners/scc.py`:
```python
import json
import subprocess
from pathlib import Path

from app.models import Metrics

NAME = "scc"
BINARY = "scc"


def run(project_path: str, workdir: Path) -> Path:
    out = workdir / "scc.json"
    proc = subprocess.run(
        [BINARY, "--format", "json", project_path],
        capture_output=True, text=True,
    )
    out.write_text(proc.stdout or "[]")
    return out


def _cocomo_months(total_code: int) -> float:
    # Basic COCOMO (organic): effort = 2.4 * KLOC^1.05 person-months.
    if total_code <= 0:
        return 0.0
    kloc = total_code / 1000.0
    return round(2.4 * (kloc ** 1.05), 2)


def parse_metrics(raw_path: Path) -> Metrics:
    langs = json.loads(Path(raw_path).read_text() or "[]")
    total_code = sum(l.get("Code", 0) for l in langs)
    return Metrics(
        total_lines=sum(l.get("Lines", 0) for l in langs),
        total_code=total_code,
        complexity=sum(l.get("Complexity", 0) for l in langs),
        cocomo_months=_cocomo_months(total_code),
        languages=langs,
    )
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_scc_runner.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/runners/scc.py tests/test_scc_runner.py tests/fixtures/scc.json
git commit -m "feat: scc metrics runner"
```

---

### Task 6: Snyk runner (SAST + dependencies)

**Files:**
- Create: `app/runners/snyk.py`
- Create: `tests/fixtures/snyk_code.json`, `tests/fixtures/snyk_deps.json`
- Test: `tests/test_snyk_runner.py`

**Interfaces:**
- Consumes: `Finding`, `normalize_severity`.
- Produces: `app.runners.snyk` with `NAME="snyk"`, `BINARY="snyk"`, `run(project_path, workdir) -> Path` (writes a combined JSON file with keys `code` and `deps`), and `parse(raw_path: Path) -> list[Finding]`.

- [ ] **Step 1: Create the Snyk fixtures**

`tests/fixtures/snyk_code.json` (SARIF from `snyk code test --json`):
```json
{
  "runs": [
    {
      "results": [
        {
          "ruleId": "python/Sqli",
          "level": "error",
          "message": {"text": "SQL Injection via string concatenation."},
          "locations": [
            {"physicalLocation": {
              "artifactLocation": {"uri": "app/db.py"},
              "region": {"startLine": 42}}}
          ]
        }
      ]
    }
  ]
}
```

`tests/fixtures/snyk_deps.json` (from `snyk test --json`):
```json
{
  "vulnerabilities": [
    {
      "id": "SNYK-PYTHON-FLASK-1",
      "title": "Denial of Service",
      "severity": "high",
      "packageName": "flask",
      "identifiers": {"CWE": ["CWE-400"]}
    }
  ]
}
```

The combined file `run()` writes wraps both: `{"code": <sarif>, "deps": <deps>}`.

- [ ] **Step 2: Write the failing test**

`tests/test_snyk_runner.py`:
```python
import json
from pathlib import Path
from app.runners import snyk


def test_parse_snyk_combined(tmp_path):
    combined = {
        "code": json.loads(Path("tests/fixtures/snyk_code.json").read_text()),
        "deps": json.loads(Path("tests/fixtures/snyk_deps.json").read_text()),
    }
    raw = tmp_path / "snyk.json"
    raw.write_text(json.dumps(combined))

    findings = snyk.parse(raw)
    assert len(findings) == 2

    code = [f for f in findings if f.file == "app/db.py"][0]
    assert code.severity == "high"
    assert code.line == 42
    assert code.rule_id == "python/Sqli"

    dep = [f for f in findings if f.rule_id == "SNYK-PYTHON-FLASK-1"][0]
    assert dep.severity == "high"
    assert dep.cwe == "CWE-400"
    assert "flask" in dep.title.lower() or "flask" in dep.description.lower()
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_snyk_runner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.runners.snyk'`.

- [ ] **Step 4: Implement snyk.py**

`app/runners/snyk.py`:
```python
import json
import subprocess
from pathlib import Path

from app.models import Finding, normalize_severity

NAME = "snyk"
BINARY = "snyk"

_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low",
                      "info": "info"}
_MANIFESTS = ["package.json", "requirements.txt", "pom.xml", "build.gradle",
              "go.mod", "Gemfile"]


def _json_cmd(args, cwd) -> dict:
    proc = subprocess.run(args, capture_output=True, text=True, cwd=cwd)
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {}


def run(project_path: str, workdir: Path) -> Path:
    out = workdir / "snyk.json"
    code = _json_cmd([BINARY, "code", "test", "--json", project_path],
                     project_path)
    deps = {}
    if any((Path(project_path) / m).exists() for m in _MANIFESTS):
        deps = _json_cmd([BINARY, "test", "--json"], project_path)
    out.write_text(json.dumps({"code": code, "deps": deps}))
    return out


def _parse_code(sarif: dict) -> list:
    findings = []
    for run_obj in sarif.get("runs", []):
        for r in run_obj.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            findings.append(Finding(
                tool=NAME,
                severity=_LEVEL_TO_SEVERITY.get(r.get("level", "warning"),
                                                "medium"),
                rule_id=r.get("ruleId", ""),
                title=r.get("ruleId", "snyk code"),
                description=r.get("message", {}).get("text", ""),
                file=loc.get("artifactLocation", {}).get("uri", ""),
                line=loc.get("region", {}).get("startLine"),
            ))
    return findings


def _parse_deps(deps: dict) -> list:
    findings = []
    for v in deps.get("vulnerabilities", []):
        cwes = (v.get("identifiers", {}) or {}).get("CWE", [])
        findings.append(Finding(
            tool=NAME,
            severity=normalize_severity(NAME, v.get("severity", "low")),
            rule_id=v.get("id", ""),
            title=f"{v.get('title', 'Dependency vulnerability')} "
                  f"({v.get('packageName', '')})",
            description=v.get("title", ""),
            file=v.get("packageName", ""),
            line=None,
            cwe=cwes[0] if cwes else None,
        ))
    return findings


def parse(raw_path: Path) -> list:
    data = json.loads(Path(raw_path).read_text() or "{}")
    return _parse_code(data.get("code", {})) + _parse_deps(data.get("deps", {}))
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_snyk_runner.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/runners/snyk.py tests/test_snyk_runner.py tests/fixtures/snyk_code.json tests/fixtures/snyk_deps.json
git commit -m "feat: snyk sast + dependency runner"
```

---

### Task 7: SonarQube runner + finalize registry

**Files:**
- Create: `app/runners/sonarqube.py`
- Modify: `app/runners/base.py` (restore full registry)
- Create: `tests/fixtures/sonar_issues.json`
- Test: `tests/test_sonarqube_runner.py`

**Interfaces:**
- Consumes: `Finding`, `normalize_severity`.
- Produces: `app.runners.sonarqube` with `NAME="sonarqube"`, `BINARY="sonar-scanner"`, `run(project_path, workdir) -> Path` (runs `sonar-scanner`, then fetches issues from the local SonarQube REST API and writes them to the raw file), and `parse(raw_path: Path) -> list[Finding]`. After this task `app.runners.base.RUNNERS` contains all four runners.

- [ ] **Step 1: Create the SonarQube fixture**

`tests/fixtures/sonar_issues.json` (shape of `/api/issues/search`):
```json
{
  "issues": [
    {
      "rule": "python:S2076",
      "severity": "BLOCKER",
      "component": "proj:app/os_cmd.py",
      "line": 8,
      "message": "OS command injection.",
      "cwe": ["CWE-78"]
    },
    {
      "rule": "python:S1481",
      "severity": "MINOR",
      "component": "proj:app/util.py",
      "line": 20,
      "message": "Unused local variable."
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

`tests/test_sonarqube_runner.py`:
```python
from pathlib import Path
from app.runners import sonarqube
from app.runners.base import RUNNERS


def test_parse_sonarqube():
    findings = sonarqube.parse(Path("tests/fixtures/sonar_issues.json"))
    assert len(findings) == 2
    crit = findings[0]
    assert crit.tool == "sonarqube"
    assert crit.severity == "critical"
    assert crit.file == "app/os_cmd.py"
    assert crit.line == 8
    assert crit.cwe == "CWE-78"
    assert findings[1].severity == "low"


def test_registry_has_all_four():
    assert set(RUNNERS) == {"semgrep", "scc", "snyk", "sonarqube"}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_sonarqube_runner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.runners.sonarqube'`.

- [ ] **Step 4: Implement sonarqube.py and restore the registry**

`app/runners/sonarqube.py`:
```python
import json
import subprocess
from pathlib import Path

import httpx

from app.models import Finding, normalize_severity

NAME = "sonarqube"
BINARY = "sonar-scanner"
SONAR_URL = "http://localhost:9000"
SONAR_TOKEN = "admin"  # local dev default; override via env in production use


def _project_key(project_path: str) -> str:
    return "scan-" + Path(project_path).name


def run(project_path: str, workdir: Path) -> Path:
    key = _project_key(project_path)
    subprocess.run(
        [BINARY,
         f"-Dsonar.projectKey={key}",
         f"-Dsonar.sources={project_path}",
         f"-Dsonar.host.url={SONAR_URL}",
         f"-Dsonar.login={SONAR_TOKEN}"],
        capture_output=True, text=True, cwd=project_path,
    )
    out = workdir / "sonar_issues.json"
    resp = httpx.get(
        f"{SONAR_URL}/api/issues/search",
        params={"componentKeys": key, "ps": 500},
        auth=(SONAR_TOKEN, ""), timeout=60,
    )
    out.write_text(resp.text if resp.status_code == 200 else '{"issues": []}')
    return out


def _strip_component(component: str) -> str:
    return component.split(":", 1)[1] if ":" in component else component


def parse(raw_path: Path) -> list:
    data = json.loads(Path(raw_path).read_text() or "{}")
    findings = []
    for i in data.get("issues", []):
        cwes = i.get("cwe", [])
        findings.append(Finding(
            tool=NAME,
            severity=normalize_severity(NAME, i.get("severity", "INFO")),
            rule_id=i.get("rule", ""),
            title=i.get("rule", "sonarqube issue"),
            description=i.get("message", ""),
            file=_strip_component(i.get("component", "")),
            line=i.get("line"),
            cwe=cwes[0] if cwes else None,
        ))
    return findings
```

Restore `app/runners/base.py`:
```python
from app.runners import semgrep, scc, snyk, sonarqube

RUNNERS = {m.NAME: m for m in (semgrep, scc, snyk, sonarqube)}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_sonarqube_runner.py -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Run the full runner suite**

Run: `pytest tests/ -v -k runner`
Expected: all runner tests PASS.

- [ ] **Step 7: Commit**

```bash
git add app/runners/sonarqube.py app/runners/base.py tests/test_sonarqube_runner.py tests/fixtures/sonar_issues.json
git commit -m "feat: sonarqube runner and complete runner registry"
```

---

### Task 8: Scan orchestration

**Files:**
- Create: `app/scanner.py`
- Test: `tests/test_scanner.py`

**Interfaces:**
- Consumes: `RUNNERS` from `app.runners.base`; db functions; `SCANS_DIR`, `TOOL_TIMEOUT_SECONDS` from `app.config`.
- Produces:
  - `preflight(project_path: str, tools: list[str]) -> list[str]` — returns a list of human-readable warnings (missing path, missing binaries); empty means all good.
  - `run_scan(conn, scan_id: int, project_path: str, tools: list[str]) -> None` — runs each selected tool concurrently, times out per `TOOL_TIMEOUT_SECONDS`, persists findings/metrics, sets per-tool status, finishes the scan. `scc` uses `parse_metrics`; others use `parse`. A tool raising/timing out is marked `failed` and does not abort the scan.

- [ ] **Step 1: Write the failing test**

`tests/test_scanner.py`:
```python
import json
from pathlib import Path
from app import db, scanner
from app.models import Finding, Metrics


class FakeRunner:
    NAME = "fake"
    BINARY = "fake-bin"

    @staticmethod
    def run(project_path, workdir):
        p = Path(workdir) / "fake.json"
        p.write_text("{}")
        return p

    @staticmethod
    def parse(raw_path):
        return [Finding(tool="fake", severity="high", rule_id="r",
                        title="t", description="d", file="a.py", line=1)]


class BoomRunner:
    NAME = "boom"
    BINARY = "boom-bin"

    @staticmethod
    def run(project_path, workdir):
        raise RuntimeError("kaboom")

    @staticmethod
    def parse(raw_path):
        return []


def test_preflight_missing_path(tmp_path):
    warns = scanner.preflight(str(tmp_path / "nope"), ["semgrep"])
    assert any("path" in w.lower() for w in warns)


def test_run_scan_persists_findings_and_continues_on_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "SCANS_DIR", tmp_path)
    monkeypatch.setattr(scanner, "RUNNERS",
                        {"fake": FakeRunner, "boom": BoomRunner})
    dbp = tmp_path / "app.db"
    db.init_db(dbp)
    conn = db.connect(dbp)
    sid = db.create_scan(conn, str(tmp_path), ["fake", "boom"])

    scanner.run_scan(conn, sid, str(tmp_path), ["fake", "boom"])

    findings = db.get_findings(conn, sid)
    assert len(findings) == 1
    status = json.loads(db.get_scan(conn, sid)["tool_status"])
    assert status["fake"]["status"] == "done"
    assert status["boom"]["status"] == "failed"
    assert db.get_scan(conn, sid)["finished_at"] is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scanner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.scanner'`.

- [ ] **Step 3: Implement scanner.py**

`app/scanner.py`:
```python
import shutil
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FTimeout
from pathlib import Path

from app import db
from app.config import SCANS_DIR, TOOL_TIMEOUT_SECONDS
from app.runners.base import RUNNERS


def preflight(project_path: str, tools: list) -> list:
    warnings = []
    if not Path(project_path).exists():
        warnings.append(f"Project path does not exist: {project_path}")
    for t in tools:
        runner = RUNNERS.get(t)
        if runner is None:
            warnings.append(f"Unknown tool: {t}")
            continue
        if shutil.which(runner.BINARY) is None:
            warnings.append(
                f"{t}: binary '{runner.BINARY}' not found on PATH; "
                f"this tool will be skipped.")
    return warnings


def _run_one(runner, project_path: str, workdir: Path):
    raw = runner.run(project_path, workdir)
    if runner.NAME == "scc":
        return ("metrics", runner.parse_metrics(raw))
    return ("findings", runner.parse(raw))


def run_scan(conn, scan_id: int, project_path: str, tools: list) -> None:
    workdir = Path(SCANS_DIR) / str(scan_id)
    workdir.mkdir(parents=True, exist_ok=True)

    available = [t for t in tools if t in RUNNERS]
    with ThreadPoolExecutor(max_workers=len(available) or 1) as ex:
        futures = {}
        for t in available:
            db.set_tool_status(conn, scan_id, t, "running")
            futures[t] = ex.submit(_run_one, RUNNERS[t], project_path, workdir)

        for t, fut in futures.items():
            try:
                kind, payload = fut.result(timeout=TOOL_TIMEOUT_SECONDS)
                if kind == "findings":
                    db.insert_findings(conn, scan_id, payload)
                else:
                    db.insert_metrics(conn, scan_id, payload)
                db.set_tool_status(conn, scan_id, t, "done")
            except FTimeout:
                db.set_tool_status(conn, scan_id, t, "failed", "timed out")
            except Exception as exc:  # tool failure must not abort the scan
                db.set_tool_status(conn, scan_id, t, "failed", str(exc))

    db.finish_scan(conn, scan_id)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_scanner.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add app/scanner.py tests/test_scanner.py
git commit -m "feat: parallel scan orchestration with preflight and per-tool isolation"
```

---

### Task 9: Scan API endpoints

**Files:**
- Modify: `app/main.py`
- Test: `tests/test_scan_api.py`

**Interfaces:**
- Consumes: `scanner`, `db`, `config` (`DB_PATH`).
- Produces:
  - `POST /api/scans` body `{"project_path": str, "tools": [str]}` → `{"scan_id": int, "warnings": [str]}`. Runs the scan **synchronously in a background thread**; returns immediately after creating the scan row (status pending/running).
  - `GET /api/scans` → `[{id, project_path, started_at, finished_at, tool_status(parsed), severity_counts}]`.
  - `GET /api/scans/{id}` → `{scan..., findings:[...], metrics:{...}|null}`.
  - Add a per-request DB connection helper `get_conn()` using `DB_PATH`; call `db.init_db(DB_PATH)` on startup.

- [ ] **Step 1: Write the failing test**

`tests/test_scan_api.py`:
```python
import time
from fastapi.testclient import TestClient
from app import main
from app.models import Finding


def _fake_run_scan(conn, scan_id, project_path, tools):
    from app import db
    db.insert_findings(conn, scan_id, [
        Finding(tool="semgrep", severity="high", rule_id="r",
                title="t", description="d", file="a.py", line=1)])
    db.set_tool_status(conn, scan_id, "semgrep", "done")
    db.finish_scan(conn, scan_id)


def test_create_and_get_scan(tmp_path, monkeypatch):
    dbp = tmp_path / "app.db"
    monkeypatch.setattr(main, "DB_PATH", dbp)
    monkeypatch.setattr(main.scanner, "preflight", lambda p, t: [])
    monkeypatch.setattr(main.scanner, "run_scan", _fake_run_scan)
    from app import db
    db.init_db(dbp)

    client = TestClient(main.app)
    resp = client.post("/api/scans",
                       json={"project_path": str(tmp_path), "tools": ["semgrep"]})
    assert resp.status_code == 200
    sid = resp.json()["scan_id"]

    for _ in range(50):
        detail = client.get(f"/api/scans/{sid}").json()
        if detail["finished_at"]:
            break
        time.sleep(0.05)
    assert len(detail["findings"]) == 1
    assert detail["findings"][0]["severity"] == "high"

    listing = client.get("/api/scans").json()
    assert listing[0]["severity_counts"]["high"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scan_api.py -v`
Expected: FAIL (endpoints return 404 / attributes missing).

- [ ] **Step 3: Implement the scan API**

Replace `app/main.py` with:
```python
import json
import threading
from dataclasses import asdict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app import db, scanner
from app.config import DB_PATH, ensure_dirs

app = FastAPI(title="Secure Code Review Dashboard")


class ScanRequest(BaseModel):
    project_path: str
    tools: list[str]


def get_conn():
    return db.connect(DB_PATH)


@app.on_event("startup")
def _startup() -> None:
    ensure_dirs()
    db.init_db(DB_PATH)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


def _severity_counts(conn, scan_id: int) -> dict:
    counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    for f in db.get_findings(conn, scan_id):
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _run_scan_thread(scan_id: int, project_path: str, tools: list):
    conn = db.connect(DB_PATH)
    try:
        scanner.run_scan(conn, scan_id, project_path, tools)
    finally:
        conn.close()


@app.post("/api/scans")
def create_scan(req: ScanRequest) -> dict:
    warnings = scanner.preflight(req.project_path, req.tools)
    conn = get_conn()
    scan_id = db.create_scan(conn, req.project_path, req.tools)
    conn.close()
    threading.Thread(target=_run_scan_thread,
                     args=(scan_id, req.project_path, req.tools),
                     daemon=True).start()
    return {"scan_id": scan_id, "warnings": warnings}


@app.get("/api/scans")
def list_scans() -> list:
    conn = get_conn()
    out = []
    for s in db.list_scans(conn):
        s["tool_status"] = json.loads(s["tool_status"])
        s["severity_counts"] = _severity_counts(conn, s["id"])
        out.append(s)
    conn.close()
    return out


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int) -> dict:
    conn = get_conn()
    scan = db.get_scan(conn, scan_id)
    if scan is None:
        conn.close()
        raise HTTPException(404, "scan not found")
    scan["tool_status"] = json.loads(scan["tool_status"])
    scan["findings"] = [asdict(f) for f in db.get_findings(conn, scan_id)]
    m = db.get_metrics(conn, scan_id)
    scan["metrics"] = asdict(m) if m else None
    conn.close()
    return scan
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_scan_api.py -v`
Expected: PASS.

- [ ] **Step 5: Run the full suite**

Run: `pytest -v`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add app/main.py tests/test_scan_api.py
git commit -m "feat: scan create/list/detail API with background execution"
```

---

### Task 10: Frontend — scan, history, results

**Files:**
- Create: `app/static/index.html`, `app/static/app.js`, `app/static/style.css`
- Modify: `app/main.py` (mount static, serve index at `/`)
- Test: `tests/test_static.py`

**Interfaces:**
- Consumes: the scan API from Task 9.
- Produces: `GET /` serves `index.html`; `/static/*` serves assets. The SPA has: New Scan form (path input + tool checkboxes), History table, and a results view with summary cards, a filterable unified findings table, per-tool tabs, and an SCC metrics panel.

- [ ] **Step 1: Write the failing test**

`tests/test_static.py`:
```python
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_index_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "Secure Code Review" in r.text


def test_static_js_served():
    r = client.get("/static/app.js")
    assert r.status_code == 200
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_static.py -v`
Expected: FAIL (404 for `/` and `/static/app.js`).

- [ ] **Step 3: Add static mounting to main.py**

Add near the top of `app/main.py` after `app = FastAPI(...)`:
```python
from pathlib import Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC / "index.html")
```

- [ ] **Step 4: Create index.html**

`app/static/index.html`:
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Secure Code Review Dashboard</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <header><h1>Secure Code Review Dashboard</h1>
    <nav><a href="#" id="nav-home">Home</a> · <a href="#" id="nav-settings">Settings</a></nav>
  </header>

  <section id="new-scan">
    <h2>New Scan</h2>
    <input id="project-path" placeholder="/absolute/path/to/project" size="60">
    <div id="tool-checks">
      <label><input type="checkbox" value="semgrep" checked> Semgrep</label>
      <label><input type="checkbox" value="sonarqube" checked> SonarQube</label>
      <label><input type="checkbox" value="snyk" checked> Snyk</label>
      <label><input type="checkbox" value="scc" checked> SCC</label>
    </div>
    <button id="run-scan">Scan</button>
    <div id="warnings"></div>
  </section>

  <section id="history"><h2>History</h2><table id="history-table"></table></section>

  <section id="results" hidden>
    <h2>Results — scan <span id="result-id"></span></h2>
    <div id="tool-chips"></div>
    <div id="summary-cards"></div>
    <div id="result-actions">
      <button id="validate-btn">Validate with AI</button>
      <span id="validate-progress"></span>
      <button id="report-btn">Generate Report</button>
    </div>
    <div id="tabs">
      <button data-tab="unified" class="tab active">Unified</button>
      <button data-tab="semgrep" class="tab">Semgrep</button>
      <button data-tab="sonarqube" class="tab">SonarQube</button>
      <button data-tab="snyk" class="tab">Snyk</button>
      <button data-tab="scc" class="tab">SCC / Metrics</button>
    </div>
    <div id="filters">
      Severity <select id="f-sev"><option value="">all</option></select>
      Tool <select id="f-tool"><option value="">all</option></select>
    </div>
    <div id="findings-panel"></div>
  </section>

  <div id="report-modal" hidden></div>
  <script src="/static/app.js"></script>
</body>
</html>
```

- [ ] **Step 5: Create style.css**

`app/static/style.css`:
```css
:root { --crit:#8b0000; --high:#c0392b; --med:#e08e0b; --low:#2e86c1; --info:#888; }
body { font-family: system-ui, sans-serif; margin: 0; color: #1a1a1a; }
header { background:#12233b; color:#fff; padding:12px 20px; display:flex;
         justify-content:space-between; align-items:center; }
header a { color:#9cc; text-decoration:none; }
section { padding: 16px 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border-bottom:1px solid #ddd; padding:6px 8px; text-align:left; font-size:14px; }
.badge { color:#fff; padding:1px 6px; border-radius:3px; font-size:12px; }
.sev-critical{background:var(--crit)} .sev-high{background:var(--high)}
.sev-medium{background:var(--med)} .sev-low{background:var(--low)} .sev-info{background:var(--info)}
#summary-cards{display:flex;gap:10px;margin:10px 0}
.card{border:1px solid #ddd;border-radius:6px;padding:10px 14px;min-width:80px}
.chip{display:inline-block;padding:2px 8px;border-radius:10px;margin:2px;font-size:12px;background:#eee}
.chip.done{background:#cfe9cf}.chip.failed{background:#f2c2c2}.chip.running{background:#fde9b0}
.tab{border:none;background:#eee;padding:6px 12px;cursor:pointer}
.tab.active{background:#12233b;color:#fff}
button{cursor:pointer}
.verdict-confirmed{color:var(--high);font-weight:bold}
.verdict-false_positive{color:#888}
.verdict-partially_true{color:var(--med)}
.verdict-inconclusive{color:#555;font-style:italic}
```

- [ ] **Step 6: Create app.js**

`app/static/app.js`:
```javascript
let currentScan = null;

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

function sevBadge(s) { return `<span class="badge sev-${s}">${s}</span>`; }

async function loadHistory() {
  const scans = await api('/api/scans');
  const rows = scans.map(s => {
    const c = s.severity_counts;
    return `<tr data-id="${s.id}"><td>${s.id}</td><td>${s.project_path}</td>
      <td>${s.started_at.slice(0,19)}</td>
      <td>${s.finished_at ? 'done' : 'running'}</td>
      <td>${sevBadge('critical')}${c.critical} ${sevBadge('high')}${c.high}
          ${sevBadge('medium')}${c.medium} ${sevBadge('low')}${c.low}</td></tr>`;
  }).join('');
  document.getElementById('history-table').innerHTML =
    `<tr><th>#</th><th>Project</th><th>Started</th><th>Status</th><th>Severity</th></tr>${rows}`;
  document.querySelectorAll('#history-table tr[data-id]').forEach(tr =>
    tr.onclick = () => openResults(Number(tr.dataset.id)));
}

async function runScan() {
  const path = document.getElementById('project-path').value.trim();
  const tools = [...document.querySelectorAll('#tool-checks input:checked')].map(c => c.value);
  const res = await api('/api/scans', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({project_path: path, tools}),
  });
  document.getElementById('warnings').innerHTML =
    res.warnings.map(w => `<div>⚠️ ${w}</div>`).join('');
  pollScan(res.scan_id);
}

async function pollScan(id) {
  const s = await api(`/api/scans/${id}`);
  if (!s.finished_at) { setTimeout(() => pollScan(id), 1500); }
  await loadHistory();
  openResults(id);
}

async function openResults(id) {
  currentScan = await api(`/api/scans/${id}`);
  document.getElementById('results').hidden = false;
  document.getElementById('result-id').textContent = id;
  const st = currentScan.tool_status;
  document.getElementById('tool-chips').innerHTML = Object.entries(st)
    .map(([t, v]) => `<span class="chip ${v.status}">${t}: ${v.status}${v.error ? ' — ' + v.error : ''}</span>`).join('');
  renderSummary();
  renderFindings('unified', '', '');
}

function renderSummary() {
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  currentScan.findings.forEach(f => counts[f.severity]++);
  const cards = Object.entries(counts).map(([s, n]) =>
    `<div class="card">${sevBadge(s)}<br><b>${n}</b></div>`).join('');
  const m = currentScan.metrics;
  const metricCard = m ? `<div class="card">Code lines<br><b>${m.total_code}</b></div>` : '';
  document.getElementById('summary-cards').innerHTML = cards + metricCard;
}

function renderFindings(tab, sevFilter, toolFilter) {
  const panel = document.getElementById('findings-panel');
  if (tab === 'scc') {
    const m = currentScan.metrics;
    panel.innerHTML = m ? `<p>Total code: ${m.total_code}, lines: ${m.total_lines},
      complexity: ${m.complexity}, COCOMO: ${m.cocomo_months} person-months</p>
      <table><tr><th>Language</th><th>Code</th><th>Complexity</th></tr>
      ${m.languages.map(l => `<tr><td>${l.Name}</td><td>${l.Code}</td><td>${l.Complexity||0}</td></tr>`).join('')}</table>`
      : '<p>No metrics.</p>';
    return;
  }
  // Dedup hint: findings across tools sharing file+line+cwe are "likely dup".
  const dupKeys = {};
  currentScan.findings.forEach(f => {
    const k = `${f.file}|${f.line}|${f.cwe || ''}`;
    dupKeys[k] = (dupKeys[k] || 0) + 1;
  });
  let items = currentScan.findings;
  if (tab !== 'unified') items = items.filter(f => f.tool === tab);
  if (sevFilter) items = items.filter(f => f.severity === sevFilter);
  if (toolFilter) items = items.filter(f => f.tool === toolFilter);
  panel.innerHTML = `<table><tr><th>Sev</th><th>Tool</th><th>File:Line</th>
    <th>Title</th><th>Verdict</th><th></th></tr>` + items.map(f => {
    const k = `${f.file}|${f.line}|${f.cwe || ''}`;
    const dup = f.cwe && dupKeys[k] > 1 ? '<span title="likely duplicate">⧉</span>' : '';
    return `<tr><td>${sevBadge(f.severity)}</td><td>${f.tool}</td>
      <td>${f.file}:${f.line ?? ''}</td><td>${f.title}</td>
      <td class="verdict-${f.verdict||''}">${f.verdict || ''}</td><td>${dup}</td></tr>`;
  }).join('') + '</table>';
}

document.getElementById('run-scan').onclick = runScan;
document.querySelectorAll('.tab').forEach(b => b.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  renderFindings(b.dataset.tab, document.getElementById('f-sev').value,
                 document.getElementById('f-tool').value);
});
['f-sev','f-tool'].forEach(id => document.getElementById(id).onchange = () => {
  const tab = document.querySelector('.tab.active').dataset.tab;
  renderFindings(tab, document.getElementById('f-sev').value,
                 document.getElementById('f-tool').value);
});
['critical','high','medium','low','info'].forEach(s => {
  document.getElementById('f-sev').innerHTML += `<option value="${s}">${s}</option>`;});
['semgrep','sonarqube','snyk'].forEach(t => {
  document.getElementById('f-tool').innerHTML += `<option value="${t}">${t}</option>`;});

loadHistory();
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_static.py -v`
Expected: PASS.

- [ ] **Step 8: Manual smoke check**

Run: `. .venv/bin/activate && uvicorn app.main:app --host 127.0.0.1 --port 8000 &` then `curl -s localhost:8000/ | grep -q "Secure Code Review" && echo OK`, then `kill %1`.
Expected: `OK`.

- [ ] **Step 9: Commit**

```bash
git add app/static/ app/main.py tests/test_static.py
git commit -m "feat: single-page frontend for scans, history, and results"
```

---

### Task 11: Settings storage and API

**Files:**
- Create: `app/settings.py`
- Modify: `app/main.py` (settings routes), `app/static/index.html` + `app.js` (settings panel)
- Test: `tests/test_settings.py`

**Interfaces:**
- Consumes: `db.get_setting`, `db.set_setting`.
- Produces:
  - `app.settings.get_provider_config(conn) -> dict` → `{"provider": str|None, "anthropic_key": str|None, "openai_key": str|None}`.
  - `app.settings.save_provider_config(conn, provider, anthropic_key, openai_key) -> None`.
  - `GET /api/settings` → provider config with keys **masked** (`"set"`/`"unset"`, never the value).
  - `POST /api/settings` body `{provider, anthropic_key, openai_key}` → `{"ok": true}`. Empty-string keys are ignored (do not overwrite an existing key).

- [ ] **Step 1: Write the failing test**

`tests/test_settings.py`:
```python
from app import db, settings


def test_save_and_get(tmp_path):
    dbp = tmp_path / "app.db"
    db.init_db(dbp)
    conn = db.connect(dbp)
    settings.save_provider_config(conn, "anthropic", "sk-ant-123", "")
    cfg = settings.get_provider_config(conn)
    assert cfg["provider"] == "anthropic"
    assert cfg["anthropic_key"] == "sk-ant-123"
    assert cfg["openai_key"] is None


def test_empty_key_does_not_overwrite(tmp_path):
    dbp = tmp_path / "app.db"
    db.init_db(dbp)
    conn = db.connect(dbp)
    settings.save_provider_config(conn, "anthropic", "sk-ant-123", "")
    settings.save_provider_config(conn, "openai", "", "")
    cfg = settings.get_provider_config(conn)
    assert cfg["anthropic_key"] == "sk-ant-123"
    assert cfg["provider"] == "openai"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_settings.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.settings'`.

- [ ] **Step 3: Implement settings.py**

`app/settings.py`:
```python
from app import db


def get_provider_config(conn) -> dict:
    return {
        "provider": db.get_setting(conn, "provider"),
        "anthropic_key": db.get_setting(conn, "anthropic_key"),
        "openai_key": db.get_setting(conn, "openai_key"),
    }


def save_provider_config(conn, provider: str, anthropic_key: str,
                         openai_key: str) -> None:
    if provider:
        db.set_setting(conn, "provider", provider)
    if anthropic_key:
        db.set_setting(conn, "anthropic_key", anthropic_key)
    if openai_key:
        db.set_setting(conn, "openai_key", openai_key)
```

- [ ] **Step 4: Add settings API to main.py**

Add to `app/main.py`:
```python
from app import settings as settings_mod


class SettingsRequest(BaseModel):
    provider: str = ""
    anthropic_key: str = ""
    openai_key: str = ""


@app.get("/api/settings")
def get_settings() -> dict:
    conn = get_conn()
    cfg = settings_mod.get_provider_config(conn)
    conn.close()
    return {
        "provider": cfg["provider"],
        "anthropic_key": "set" if cfg["anthropic_key"] else "unset",
        "openai_key": "set" if cfg["openai_key"] else "unset",
    }


@app.post("/api/settings")
def save_settings(req: SettingsRequest) -> dict:
    conn = get_conn()
    settings_mod.save_provider_config(conn, req.provider, req.anthropic_key,
                                      req.openai_key)
    conn.close()
    return {"ok": True}
```

- [ ] **Step 5: Add the settings panel to the frontend**

In `app/static/index.html`, add before `<div id="report-modal"`:
```html
<section id="settings" hidden>
  <h2>Settings</h2>
  <label>Provider
    <select id="s-provider"><option value="anthropic">Anthropic</option>
      <option value="openai">OpenAI</option></select></label><br>
  <label>Anthropic API key <input id="s-anthropic" type="password" placeholder="leave blank to keep"></label><br>
  <label>OpenAI API key <input id="s-openai" type="password" placeholder="leave blank to keep"></label><br>
  <button id="save-settings">Save</button>
  <div id="settings-status"></div>
</section>
```

Append to `app/static/app.js`:
```javascript
async function showSettings() {
  const cfg = await api('/api/settings');
  document.getElementById('s-provider').value = cfg.provider || 'anthropic';
  document.getElementById('settings-status').textContent =
    `Anthropic key: ${cfg.anthropic_key}, OpenAI key: ${cfg.openai_key}`;
  document.getElementById('settings').hidden = false;
}
document.getElementById('nav-settings').onclick = showSettings;
document.getElementById('nav-home').onclick = () =>
  document.getElementById('settings').hidden = true;
document.getElementById('save-settings').onclick = async () => {
  await api('/api/settings', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      provider: document.getElementById('s-provider').value,
      anthropic_key: document.getElementById('s-anthropic').value,
      openai_key: document.getElementById('s-openai').value})});
  showSettings();
};
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_settings.py -v`
Expected: PASS (2 passed).

- [ ] **Step 7: Commit**

```bash
git add app/settings.py app/main.py app/static/ tests/test_settings.py
git commit -m "feat: AI provider settings storage, API, and panel"
```

---

### Task 12: AI Validate — provider base and context builder

**Files:**
- Create: `app/validator/__init__.py`, `app/validator/base.py`
- Test: `tests/test_validator_base.py`

**Interfaces:**
- Consumes: `Finding` from `app.models`.
- Produces:
  - `app.validator.base.Verdict` dataclass: `verdict: str, confidence: str, verdict_note: str, impact_text: str, recommendation: str, cwe: str | None`.
  - `build_code_context(project_path: str, file: str, line: int | None, radius: int = 15) -> str` — returns ±`radius` numbered source lines around `line`, or `""` if the file can't be read.
  - `build_prompt(finding: Finding, code_context: str) -> str` — the user-message text.
  - `VERDICT_SCHEMA: dict` — JSON schema for structured output (fields: verdict enum, confidence enum, verdict_note, impact_text, recommendation, cwe).

- [ ] **Step 1: Write the failing test**

`tests/test_validator_base.py`:
```python
from app.validator import base
from app.models import Finding


def test_build_code_context(tmp_path):
    src = tmp_path / "a.py"
    src.write_text("\n".join(f"line{i}" for i in range(1, 41)))
    ctx = base.build_code_context(str(tmp_path), "a.py", 20, radius=2)
    assert "line18" in ctx and "line22" in ctx
    assert "line10" not in ctx
    assert "20:" in ctx  # numbered


def test_build_code_context_missing_file(tmp_path):
    assert base.build_code_context(str(tmp_path), "nope.py", 5) == ""


def test_build_prompt_mentions_finding(tmp_path):
    f = Finding(tool="semgrep", severity="high", rule_id="r1",
                title="SQLi", description="bad", file="a.py", line=3)
    p = base.build_prompt(f, "3: q = 'SELECT ' + x")
    assert "SQLi" in p and "a.py" in p and "SELECT" in p


def test_schema_shape():
    props = base.VERDICT_SCHEMA["properties"]
    assert set(["verdict", "confidence", "verdict_note", "impact_text",
                "recommendation", "cwe"]).issubset(props)
    assert props["verdict"]["enum"] == ["confirmed", "partially_true",
                                        "false_positive"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_validator_base.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.validator'`.

- [ ] **Step 3: Implement base.py**

`app/validator/__init__.py`: (empty file)

`app/validator/base.py`:
```python
from dataclasses import dataclass
from pathlib import Path

from app.models import Finding


@dataclass
class Verdict:
    verdict: str
    confidence: str
    verdict_note: str
    impact_text: str
    recommendation: str
    cwe: str | None = None


VERDICT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "confidence", "verdict_note", "impact_text",
                 "recommendation", "cwe"],
    "properties": {
        "verdict": {"type": "string",
                    "enum": ["confirmed", "partially_true", "false_positive"]},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "verdict_note": {"type": "string"},
        "impact_text": {"type": "string"},
        "recommendation": {"type": "string"},
        "cwe": {"type": ["string", "null"]},
    },
}


def build_code_context(project_path: str, file: str, line: int | None,
                       radius: int = 15) -> str:
    if not line:
        return ""
    target = Path(project_path) / file
    try:
        lines = target.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))


def build_prompt(finding: Finding, code_context: str) -> str:
    return (
        "You are a security code reviewer. Decide whether the following "
        "static-analysis finding is a true or false positive, based on the "
        "code context.\n\n"
        f"Tool: {finding.tool}\nRule: {finding.rule_id}\n"
        f"Reported severity: {finding.severity}\n"
        f"Title: {finding.title}\nMessage: {finding.description}\n"
        f"Location: {finding.file}:{finding.line}\n\n"
        f"Code context:\n{code_context or '(source unavailable)'}\n\n"
        "Return your assessment as structured JSON with a verdict "
        "(confirmed / partially_true / false_positive), a confidence level, "
        "a short justification (verdict_note), the technical impact "
        "(impact_text), a remediation (recommendation), and a CWE id if you "
        "can identify one (else null)."
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_validator_base.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add app/validator/ tests/test_validator_base.py
git commit -m "feat: AI validate verdict schema, code context, and prompt builder"
```

---

### Task 13: AI Validate — provider adapters

**Files:**
- Create: `app/validator/providers/__init__.py`, `app/validator/providers/anthropic.py`, `app/validator/providers/openai.py`
- Test: `tests/test_providers.py`

**Interfaces:**
- Consumes: `Verdict`, `VERDICT_SCHEMA`, `build_prompt` from `app.validator.base`.
- Produces:
  - `anthropic.validate(prompt: str, api_key: str) -> Verdict`
  - `openai.validate(prompt: str, api_key: str) -> Verdict`
  - Each parses the model's structured JSON into a `Verdict`. On an Anthropic `stop_reason == "refusal"` (after the built-in fallback), return `Verdict(verdict="inconclusive", confidence="low", verdict_note="Model declined to assess this finding.", impact_text="", recommendation="", cwe=None)`.
  - Both expose `_verdict_from_json(data: dict) -> Verdict` (pure, unit-tested without network).

- [ ] **Step 1: Write the failing test**

`tests/test_providers.py`:
```python
from app.validator.providers import anthropic as anth
from app.validator.providers import openai as oai


def test_anthropic_verdict_from_json():
    data = {"verdict": "confirmed", "confidence": "high", "verdict_note": "n",
            "impact_text": "i", "recommendation": "r", "cwe": "CWE-89"}
    v = anth._verdict_from_json(data)
    assert v.verdict == "confirmed"
    assert v.cwe == "CWE-89"


def test_openai_verdict_from_json_null_cwe():
    data = {"verdict": "false_positive", "confidence": "medium",
            "verdict_note": "n", "impact_text": "i", "recommendation": "r",
            "cwe": None}
    v = oai._verdict_from_json(data)
    assert v.verdict == "false_positive"
    assert v.cwe is None


def test_anthropic_refusal_helper():
    v = anth._refusal_verdict()
    assert v.verdict == "inconclusive"
    assert v.confidence == "low"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_providers.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.validator.providers'`.

- [ ] **Step 3: Implement the providers**

`app/validator/providers/__init__.py`: (empty file)

`app/validator/providers/anthropic.py`:
```python
import json

import anthropic

from app.validator.base import VERDICT_SCHEMA, Verdict

MODEL = "claude-opus-4-8"


def _verdict_from_json(data: dict) -> Verdict:
    return Verdict(
        verdict=data["verdict"], confidence=data["confidence"],
        verdict_note=data["verdict_note"], impact_text=data["impact_text"],
        recommendation=data["recommendation"], cwe=data.get("cwe"),
    )


def _refusal_verdict() -> Verdict:
    return Verdict(verdict="inconclusive", confidence="low",
                   verdict_note="Model declined to assess this finding.",
                   impact_text="", recommendation="", cwe=None)


def validate(prompt: str, api_key: str) -> Verdict:
    client = anthropic.Anthropic(api_key=api_key)
    resp = client.beta.messages.create(
        model=MODEL,
        max_tokens=1024,
        betas=["server-side-fallback-2026-06-01"],
        fallbacks=[{"model": "claude-opus-4-8"}],
        output_config={"format": {"type": "json_schema",
                                  "schema": VERDICT_SCHEMA}},
        messages=[{"role": "user", "content": prompt}],
    )
    if resp.stop_reason == "refusal":
        return _refusal_verdict()
    text = next((b.text for b in resp.content if b.type == "text"), "{}")
    return _verdict_from_json(json.loads(text))
```

`app/validator/providers/openai.py`:
```python
import json

from openai import OpenAI

from app.validator.base import VERDICT_SCHEMA, Verdict

MODEL = "gpt-4o"


def _verdict_from_json(data: dict) -> Verdict:
    return Verdict(
        verdict=data["verdict"], confidence=data["confidence"],
        verdict_note=data["verdict_note"], impact_text=data["impact_text"],
        recommendation=data["recommendation"], cwe=data.get("cwe"),
    )


def validate(prompt: str, api_key: str) -> Verdict:
    client = OpenAI(api_key=api_key)
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        response_format={
            "type": "json_schema",
            "json_schema": {"name": "verdict", "strict": True,
                            "schema": VERDICT_SCHEMA},
        },
    )
    data = json.loads(resp.choices[0].message.content)
    return _verdict_from_json(data)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_providers.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add app/validator/providers/ tests/test_providers.py
git commit -m "feat: anthropic and openai validate adapters with structured output"
```

---

### Task 14: AI Validate — orchestration service and API

**Files:**
- Create: `app/validator/service.py`
- Modify: `app/main.py` (validate route), `app/static/app.js` (validate button)
- Test: `tests/test_validate_service.py`

**Interfaces:**
- Consumes: `db`, `settings`, `base.build_code_context`, `base.build_prompt`; provider modules keyed by name.
- Produces:
  - `app.validator.service.PROVIDERS: dict[str, callable]` → `{"anthropic": anthropic.validate, "openai": openai.validate}`.
  - `validate_scan(conn, scan_id: int, project_path: str, provider_fn, api_key: str, concurrency: int = 5) -> dict` — validates every finding of the scan concurrently (bounded), writes each verdict via `db.update_finding_verdict`, and returns `{"validated": int, "verdicts": {finding_id: verdict_str}}`. A finding whose provider call raises is stored as `inconclusive` (note = the error) and does not abort the batch.
  - `POST /api/scans/{id}/validate` → runs validation using the configured provider + stored key; 400 if no key configured. Returns the summary dict.

- [ ] **Step 1: Write the failing test**

`tests/test_validate_service.py`:
```python
from app import db
from app.validator import service
from app.validator.base import Verdict
from app.models import Finding


def _seed(tmp_path):
    dbp = tmp_path / "app.db"
    db.init_db(dbp)
    conn = db.connect(dbp)
    sid = db.create_scan(conn, str(tmp_path), ["semgrep"])
    db.insert_findings(conn, sid, [
        Finding(tool="semgrep", severity="high", rule_id="r1",
                title="SQLi", description="d", file="a.py", line=1),
        Finding(tool="semgrep", severity="low", rule_id="r2",
                title="print", description="d", file="b.py", line=2),
    ])
    return conn, sid


def test_validate_scan_writes_verdicts(tmp_path):
    conn, sid = _seed(tmp_path)

    def fake_provider(prompt, api_key):
        return Verdict("confirmed", "high", "n", "i", "fix", "CWE-89")

    summary = service.validate_scan(conn, sid, str(tmp_path),
                                    fake_provider, "key", concurrency=2)
    assert summary["validated"] == 2
    findings = db.get_findings(conn, sid)
    assert all(f.verdict == "confirmed" for f in findings)
    assert findings[0].cwe == "CWE-89"


def test_provider_error_becomes_inconclusive(tmp_path):
    conn, sid = _seed(tmp_path)

    def boom_provider(prompt, api_key):
        raise RuntimeError("api down")

    service.validate_scan(conn, sid, str(tmp_path), boom_provider, "key")
    findings = db.get_findings(conn, sid)
    assert all(f.verdict == "inconclusive" for f in findings)
    assert "api down" in findings[0].verdict_note
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_validate_service.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.validator.service'`.

- [ ] **Step 3: Implement service.py**

`app/validator/service.py`:
```python
from concurrent.futures import ThreadPoolExecutor

from app import db
from app.validator import base
from app.validator.base import Verdict
from app.validator.providers import anthropic as anthropic_provider
from app.validator.providers import openai as openai_provider

PROVIDERS = {
    "anthropic": anthropic_provider.validate,
    "openai": openai_provider.validate,
}


def _validate_one(finding, project_path, provider_fn, api_key) -> Verdict:
    ctx = base.build_code_context(project_path, finding.file, finding.line)
    prompt = base.build_prompt(finding, ctx)
    try:
        return provider_fn(prompt, api_key)
    except Exception as exc:  # provider error must not abort the batch
        return Verdict("inconclusive", "low", f"Validation error: {exc}",
                       "", "", None)


def validate_scan(conn, scan_id: int, project_path: str, provider_fn,
                  api_key: str, concurrency: int = 5) -> dict:
    findings = db.get_findings(conn, scan_id)
    verdicts = {}
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = {ex.submit(_validate_one, f, project_path, provider_fn, api_key): f
                for f in findings}
        for fut, f in futs.items():
            v = fut.result()
            db.update_finding_verdict(conn, f.id, v.verdict, v.confidence,
                                      v.verdict_note, v.impact_text,
                                      v.recommendation, v.cwe)
            verdicts[f.id] = v.verdict
    return {"validated": len(findings), "verdicts": verdicts}
```

- [ ] **Step 4: Add the validate API to main.py**

Add to `app/main.py`:
```python
from app.validator import service as validate_service


@app.post("/api/scans/{scan_id}/validate")
def validate_scan_endpoint(scan_id: int) -> dict:
    conn = get_conn()
    scan = db.get_scan(conn, scan_id)
    if scan is None:
        conn.close()
        raise HTTPException(404, "scan not found")
    cfg = settings_mod.get_provider_config(conn)
    provider = cfg["provider"]
    key = cfg.get(f"{provider}_key") if provider else None
    if not provider or not key:
        conn.close()
        raise HTTPException(400, "No AI provider/key configured in Settings.")
    provider_fn = validate_service.PROVIDERS[provider]
    summary = validate_service.validate_scan(
        conn, scan_id, scan["project_path"], provider_fn, key)
    conn.close()
    return summary
```

- [ ] **Step 5: Wire the validate button in app.js**

Append to `app/static/app.js`:
```javascript
document.getElementById('validate-btn').onclick = async () => {
  if (!currentScan) return;
  const p = document.getElementById('validate-progress');
  p.textContent = 'validating…';
  try {
    const res = await api(`/api/scans/${currentScan.id}/validate`, {method: 'POST'});
    p.textContent = `validated ${res.validated} findings`;
    await openResults(currentScan.id);
  } catch (e) { p.textContent = 'error: ' + e.message; }
};
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_validate_service.py -v`
Expected: PASS (2 passed).

- [ ] **Step 7: Commit**

```bash
git add app/validator/service.py app/main.py app/static/app.js tests/test_validate_service.py
git commit -m "feat: AI validate orchestration service and endpoint"
```

---

### Task 15: Report generation

**Files:**
- Create: `app/report/__init__.py`, `app/report/generator.py`, `app/report/template.html`
- Modify: `app/main.py` (report routes), `app/static/app.js` (report modal)
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `Finding`, `Metrics`, `db`, `SCANS_DIR`.
- Produces:
  - `app.report.generator.build_data(findings: list[Finding], meta: dict, include_false_positives: bool) -> dict` — returns the `DATA` dict with keys `F` (list of finding dicts using the template's field names: `title, risk, component, category, description, code, impactText, location, line, parameter, recommendation, ref, verdict, verdictNote, confidence, cwe`), `CWE` (title→cwe map), and `LOCS` (`{}` for now). Filters findings by verdict per `include_false_positives`.
  - `render_report(data: dict, meta: dict) -> str` — renders `template.html` with the embedded `DATA` JSON and metadata.
  - `generate(conn, scan_id: int, meta: dict, include_false_positives: bool) -> str` — builds data from the scan's findings, renders, writes `data/scans/<id>/report-<n>.html`, records it via `db.create_report`, returns the file path.
  - `POST /api/scans/{id}/report` body `{meta: {...}, include_false_positives: bool}` → `{"path": str, "report_id": int}`; `GET /api/reports/{report_id}` serves the HTML file.

- [ ] **Step 1: Create the template**

Create `app/report/template.html` by copying the reference report structure. Run:
```bash
cp /home/kali/Vulnerability-Report.HTML app/report/template.html
```
Then edit `app/report/template.html`: locate the embedded `const DATA = {...}` script block and the metadata header text, and replace them with Jinja2 placeholders so the generator injects fresh values. The two edits are:

1. Replace the entire `const DATA = { ... };` assignment with:
```html
<script>const DATA = {{ data_json | safe }};</script>
```
2. Replace the metadata header values (client/program, assessment type, repos, report date) with `{{ meta.client }}`, `{{ meta.assessment_type }}`, `{{ meta.repos }}`, `{{ meta.report_date }}`.

Leave the `<style>` block, the rendering JavaScript, and all DOM scaffolding unchanged — the report stays self-contained and print-ready.

- [ ] **Step 2: Write the failing test**

`tests/test_report.py`:
```python
from app.report import generator
from app.models import Finding


def _findings():
    return [
        Finding(tool="semgrep", severity="high", rule_id="r1", title="SQLi",
                description="d", file="a.py", line=5, cwe="CWE-89",
                verdict="confirmed", confidence="high", verdict_note="n",
                impact_text="i", recommendation="fix"),
        Finding(tool="semgrep", severity="low", rule_id="r2", title="Noise",
                description="d", file="b.py", line=2, verdict="false_positive"),
    ]


def test_build_data_default_excludes_false_positives():
    data = generator.build_data(_findings(), {}, include_false_positives=False)
    assert len(data["F"]) == 1
    entry = data["F"][0]
    assert entry["title"] == "SQLi"
    assert entry["risk"] == "high"
    assert entry["location"] == "a.py"
    assert entry["verdict"] == "confirmed"
    assert data["CWE"]["SQLi"] == "CWE-89"


def test_build_data_include_false_positives():
    data = generator.build_data(_findings(), {}, include_false_positives=True)
    assert len(data["F"]) == 2


def test_render_report_embeds_data_and_meta(tmp_path, monkeypatch):
    # minimal template so the test doesn't depend on the 188KB reference
    tpl = tmp_path / "template.html"
    tpl.write_text("<h1>{{ meta.client }}</h1>"
                   "<script>const DATA = {{ data_json | safe }};</script>")
    monkeypatch.setattr(generator, "TEMPLATE_PATH", tpl)
    html = generator.render_report({"F": [], "CWE": {}, "LOCS": {}},
                                   {"client": "AcmeCorp"})
    assert "AcmeCorp" in html
    assert '"F":' in html or '"F": []' in html
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_report.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.report'`.

- [ ] **Step 4: Implement generator.py**

`app/report/__init__.py`: (empty file)

`app/report/generator.py`:
```python
import json
from pathlib import Path

from jinja2 import Template

from app import db
from app.config import SCANS_DIR

TEMPLATE_PATH = Path(__file__).parent / "template.html"

_INCLUDED_VERDICTS = {"confirmed", "partially_true"}


def _to_entry(f) -> dict:
    return {
        "title": f.title,
        "risk": f.severity,
        "component": f.tool,
        "category": f.rule_id,
        "description": f.description,
        "code": "",
        "impactText": f.impact_text or "",
        "location": f.file,
        "line": f.line,
        "parameter": "",
        "recommendation": f.recommendation or "",
        "ref": "",
        "verdict": f.verdict or "",
        "verdictNote": f.verdict_note or "",
        "confidence": f.confidence or "",
        "cwe": f.cwe or "",
    }


def build_data(findings: list, meta: dict, include_false_positives: bool) -> dict:
    selected = []
    for f in findings:
        if f.verdict in _INCLUDED_VERDICTS:
            selected.append(f)
        elif include_false_positives and f.verdict in ("false_positive",
                                                       "inconclusive"):
            selected.append(f)
        elif f.verdict is None:
            selected.append(f)  # unvalidated findings still appear
    entries = [_to_entry(f) for f in selected]
    cwe_map = {f.title: f.cwe for f in selected if f.cwe}
    return {"F": entries, "CWE": cwe_map, "LOCS": {}}


def render_report(data: dict, meta: dict) -> str:
    template = Template(Path(TEMPLATE_PATH).read_text())
    return template.render(data_json=json.dumps(data), meta=meta)


def generate(conn, scan_id: int, meta: dict,
             include_false_positives: bool) -> str:
    findings = db.get_findings(conn, scan_id)
    data = build_data(findings, meta, include_false_positives)
    html = render_report(data, meta)
    workdir = Path(SCANS_DIR) / str(scan_id)
    workdir.mkdir(parents=True, exist_ok=True)
    n = len(db.list_reports(conn, scan_id)) + 1
    out = workdir / f"report-{n}.html"
    out.write_text(html)
    db.create_report(conn, scan_id, str(out), json.dumps(meta))
    return str(out)
```

- [ ] **Step 5: Add report API to main.py**

Add to `app/main.py`:
```python
from app.report import generator as report_generator


class ReportRequest(BaseModel):
    meta: dict = {}
    include_false_positives: bool = False


@app.post("/api/scans/{scan_id}/report")
def create_report_endpoint(scan_id: int, req: ReportRequest) -> dict:
    conn = get_conn()
    scan = db.get_scan(conn, scan_id)
    if scan is None:
        conn.close()
        raise HTTPException(404, "scan not found")
    meta = dict(req.meta)
    meta.setdefault("report_date", scan["started_at"][:10])
    path = report_generator.generate(conn, scan_id, meta,
                                     req.include_false_positives)
    report_id = db.list_reports(conn, scan_id)[0]["id"]
    conn.close()
    return {"path": path, "report_id": report_id}


@app.get("/api/reports/{report_id}")
def get_report(report_id: int):
    conn = get_conn()
    row = conn.execute("SELECT * FROM reports WHERE id=?",
                       (report_id,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(404, "report not found")
    return FileResponse(row["path"], media_type="text/html")
```

- [ ] **Step 6: Wire the report button in app.js**

Append to `app/static/app.js`:
```javascript
document.getElementById('report-btn').onclick = async () => {
  if (!currentScan) return;
  const client = prompt('Client / program name:', '') || '';
  const atype = prompt('Assessment type:', 'White-box source code review') || '';
  const includeFp = confirm('Include false positives in an appendix?');
  const res = await api(`/api/scans/${currentScan.id}/report`, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({meta: {client, assessment_type: atype,
      repos: currentScan.project_path}, include_false_positives: includeFp})});
  window.open(`/api/reports/${res.report_id}`, '_blank');
};
```

- [ ] **Step 7: Run test to verify it passes**

Run: `pytest tests/test_report.py -v`
Expected: PASS (3 passed).

- [ ] **Step 8: Commit**

```bash
git add app/report/ app/main.py app/static/app.js tests/test_report.py
git commit -m "feat: HTML vulnerability report generation from validated findings"
```

---

### Task 16: End-to-end integration test and Docker compose

**Files:**
- Create: `docker-compose.yml`, `tests/test_integration.py`, `tests/fixtures/vuln_project/app.py`
- Test: `tests/test_integration.py`

**Interfaces:**
- Consumes: the full stack via `TestClient`, with the scanner monkeypatched to a stub runner (no live tools) and validation monkeypatched to a stub provider (no live API). Verifies: scan → findings persisted → validate → verdicts persisted → report renders and is downloadable.

- [ ] **Step 1: Create the deliberately-vulnerable sample project**

`tests/fixtures/vuln_project/app.py`:
```python
import os


def run(cmd):
    os.system("echo " + cmd)  # command injection smell
```

- [ ] **Step 2: Create docker-compose.yml**

`docker-compose.yml`:
```yaml
services:
  sonarqube:
    image: sonarqube:community
    ports:
      - "9000:9000"
    environment:
      - SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_extensions:/opt/sonarqube/extensions
volumes:
  sonarqube_data:
  sonarqube_extensions:
```

- [ ] **Step 3: Write the integration test**

`tests/test_integration.py`:
```python
import time
from pathlib import Path
from fastapi.testclient import TestClient
from app import main, db
from app.models import Finding
from app.validator.base import Verdict


def _stub_run_scan(conn, scan_id, project_path, tools):
    db.insert_findings(conn, scan_id, [
        Finding(tool="semgrep", severity="critical", rule_id="cmd-inj",
                title="Command Injection", description="os.system with input",
                file="app.py", line=5)])
    db.set_tool_status(conn, scan_id, "semgrep", "done")
    db.finish_scan(conn, scan_id)


def _stub_provider(prompt, api_key):
    return Verdict("confirmed", "high", "Reachable with user input.",
                   "RCE", "Use subprocess with a list.", "CWE-78")


def test_end_to_end(tmp_path, monkeypatch):
    dbp = tmp_path / "app.db"
    monkeypatch.setattr(main, "DB_PATH", dbp)
    monkeypatch.setattr(main.scanner, "preflight", lambda p, t: [])
    monkeypatch.setattr(main.scanner, "run_scan", _stub_run_scan)
    monkeypatch.setattr(main.validate_service, "PROVIDERS",
                        {"anthropic": _stub_provider})
    monkeypatch.setattr(main.report_generator, "SCANS_DIR", tmp_path)
    db.init_db(dbp)
    conn = db.connect(dbp)
    main.settings_mod.save_provider_config(conn, "anthropic", "sk-test", "")
    conn.close()

    client = TestClient(main.app)
    proj = str(Path("tests/fixtures/vuln_project"))
    sid = client.post("/api/scans",
                      json={"project_path": proj, "tools": ["semgrep"]}
                      ).json()["scan_id"]

    for _ in range(50):
        detail = client.get(f"/api/scans/{sid}").json()
        if detail["finished_at"]:
            break
        time.sleep(0.05)
    assert len(detail["findings"]) == 1

    vres = client.post(f"/api/scans/{sid}/validate").json()
    assert vres["validated"] == 1
    detail = client.get(f"/api/scans/{sid}").json()
    assert detail["findings"][0]["verdict"] == "confirmed"

    rres = client.post(f"/api/scans/{sid}/report",
                       json={"meta": {"client": "Acme"},
                             "include_false_positives": False}).json()
    report = client.get(f"/api/reports/{rres['report_id']}")
    assert report.status_code == 200
    assert "Acme" in report.text
```

- [ ] **Step 4: Run test to verify it fails, then passes**

Run: `pytest tests/test_integration.py -v`
Expected: initially may FAIL if `main.report_generator.SCANS_DIR` monkeypatch target differs; adjust the monkeypatch to `app.report.generator.SCANS_DIR` if needed, then it should PASS.

- [ ] **Step 5: Run the full suite**

Run: `pytest -v`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yml tests/test_integration.py tests/fixtures/vuln_project/
git commit -m "test: end-to-end scan-validate-report integration + sonarqube compose"
```

---

## Setup Notes (one-time, outside the TDD loop)

These are environment steps the operator runs once; they are not test-driven:

- Install tools: `pip install semgrep`, install SCC binary, install Snyk CLI (`npm i -g snyk` then `snyk auth`), install `sonar-scanner`, and `docker compose up -d sonarqube` (first boot ~1–2 min; create a token and set `SONAR_TOKEN` in `app/runners/sonarqube.py` or via env for real scans).
- Run the app: `. .venv/bin/activate && uvicorn app.main:app --host 127.0.0.1 --port 8000`.
- Enter your Anthropic or OpenAI key on the Settings page before using Validate with AI.
