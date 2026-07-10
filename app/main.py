import json
import threading
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import db, scanner, settings as settings_mod
from app.config import DB_PATH, ensure_dirs
from app.report import generator as report_generator
from app.validator import service as validate_service

app = FastAPI(title="Secure Code Review Dashboard")

_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


class ScanRequest(BaseModel):
    project_path: str
    tools: list[str]


class SettingsRequest(BaseModel):
    provider: str = ""
    anthropic_key: str = ""
    openai_key: str = ""


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
    meta.setdefault("client", "")
    meta.setdefault("assessment_type", "")
    meta.setdefault("repos", "")
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
