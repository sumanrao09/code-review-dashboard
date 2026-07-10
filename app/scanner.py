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
