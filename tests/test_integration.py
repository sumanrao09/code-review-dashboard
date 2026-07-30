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
    main.settings_mod.save_provider_config(conn, "anthropic",
                                           {"anthropic": "sk-test"})
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

    # per-finding validation returns the updated finding
    fid = detail["findings"][0]["id"]
    fres = client.post(f"/api/findings/{fid}/validate").json()
    assert fres["id"] == fid
    assert fres["verdict"] == "confirmed"
    assert fres["recommendation"] == "Use subprocess with a list."

    rres = client.post(f"/api/scans/{sid}/report",
                       json={"meta": {"client": "Acme"},
                             "include_false_positives": False}).json()
    report = client.get(f"/api/reports/{rres['report_id']}")
    assert report.status_code == 200
    assert "Acme" in report.text
