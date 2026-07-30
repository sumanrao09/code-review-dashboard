import json
import os
import threading
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import db, folderpick, profiler, scanner, settings as settings_mod
from app.runners import sonar_auth
from app.config import DB_PATH, ensure_dirs
from app.report import generator as report_generator
from app.validator import service as validate_service

app = FastAPI(title="Secure Code Review Dashboard")

_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


class AnalyzeRequest(BaseModel):
    project_path: str


class ScanRequest(BaseModel):
    project_path: str
    tools: list[str]


class SettingsRequest(BaseModel):
    provider: str = ""
    anthropic_key: str = ""
    openai_key: str = ""
    gemini_key: str = ""
    deepseek_key: str = ""
    grok_key: str = ""
    sonar_token: str = ""
    snyk_token: str = ""


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


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest) -> dict:
    """Step 1: profile the codebase with SCC and recommend a scan config."""
    return profiler.analyze(req.project_path)


@app.post("/api/pick-folder")
def pick_folder_endpoint() -> dict:
    """Open a native folder picker on this machine (local single-user app)."""
    if os.environ.get("RUNNING_IN_DOCKER"):
        raise HTTPException(
            501, "Folder picker isn't available in Docker — type a path under "
                 "/projects (your repos mounted via SCAN_ROOT).")
    try:
        path = folderpick.pick_folder()
    except folderpick.PickerBusyError as exc:
        raise HTTPException(409, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"Folder picker unavailable: {exc}")
    return {"path": path}


@app.post("/api/scans")
def create_scan(req: ScanRequest) -> dict:
    warnings = scanner.preflight(req.project_path, req.tools)
    conn = get_conn()
    if "sonarqube" in req.tools:
        # Auto-provision a token from a default-credential server if needed.
        warnings += sonar_auth.ensure_token(conn)
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
    sonar = sonar_auth.stored_token(conn)
    snyk_tok = db.get_setting(conn, "snyk_token")
    conn.close()
    out = {"provider": cfg["provider"]}
    for p in settings_mod.KEYED_PROVIDERS:
        out[f"{p}_key"] = "set" if cfg.get(f"{p}_key") else "unset"
    out["sonar_token"] = "set" if sonar else "unset"
    out["snyk_token"] = "set" if snyk_tok else "unset"
    return out


@app.post("/api/settings")
def save_settings(req: SettingsRequest) -> dict:
    conn = get_conn()
    settings_mod.save_provider_config(conn, req.provider, {
        "anthropic": req.anthropic_key,
        "openai": req.openai_key,
        "gemini": req.gemini_key,
        "deepseek": req.deepseek_key,
        "grok": req.grok_key,
    })
    if req.sonar_token:
        sonar_auth.store_token(conn, req.sonar_token)
    if req.snyk_token:
        db.set_setting(conn, "snyk_token", req.snyk_token)
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


def _resolve_provider(cfg) -> tuple:
    """Return (provider_fn, api_key) for the configured provider or raise 400."""
    provider = cfg.get("provider")
    if not provider or provider not in validate_service.PROVIDERS:
        raise HTTPException(400, "No AI provider configured in Settings.")
    if provider in settings_mod.KEYLESS_PROVIDERS:
        return validate_service.PROVIDERS[provider], ""
    key = cfg.get(f"{provider}_key")
    if not key:
        raise HTTPException(400, f"No API key stored for '{provider}' in Settings.")
    return validate_service.PROVIDERS[provider], key


@app.post("/api/scans/{scan_id}/validate")
def validate_scan_endpoint(scan_id: int) -> dict:
    conn = get_conn()
    scan = db.get_scan(conn, scan_id)
    if scan is None:
        conn.close()
        raise HTTPException(404, "scan not found")
    try:
        provider_fn, key = _resolve_provider(settings_mod.get_provider_config(conn))
    except HTTPException:
        conn.close()
        raise
    summary = validate_service.validate_scan(
        conn, scan_id, scan["project_path"], provider_fn, key)
    conn.close()
    return summary


@app.post("/api/findings/{finding_id}/validate")
def validate_finding_endpoint(finding_id: int) -> dict:
    """Validate a single finding with the configured AI provider."""
    conn = get_conn()
    finding = db.get_finding(conn, finding_id)
    if finding is None:
        conn.close()
        raise HTTPException(404, "finding not found")
    scan = db.get_scan(conn, finding.scan_id)
    try:
        provider_fn, key = _resolve_provider(settings_mod.get_provider_config(conn))
    except HTTPException:
        conn.close()
        raise
    validate_service.validate_finding(conn, finding, scan["project_path"],
                                      provider_fn, key)
    updated = db.get_finding(conn, finding_id)
    conn.close()
    return asdict(updated)
