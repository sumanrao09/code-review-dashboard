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


def test_triage_and_context_endpoints(tmp_path, monkeypatch):
    dbp = tmp_path / "app.db"
    monkeypatch.setattr(main, "DB_PATH", dbp)
    monkeypatch.setattr(main.scanner, "preflight", lambda p, t: [])
    monkeypatch.setattr(main.scanner, "run_scan", _fake_run_scan)
    from app import db
    db.init_db(dbp)
    (tmp_path / "a.py").write_text("import os\nos.system(x)\nprint('ok')\n")

    client = TestClient(main.app)
    sid = client.post("/api/scans",
                      json={"project_path": str(tmp_path),
                            "tools": ["semgrep"]}).json()["scan_id"]
    for _ in range(50):
        detail = client.get(f"/api/scans/{sid}").json()
        if detail["finished_at"]:
            break
        time.sleep(0.05)
    finding = detail["findings"][0]
    fid = finding["id"]
    assert finding["triage"] == "open"  # default

    # --- triage ---
    r = client.post(f"/api/findings/{fid}/triage", json={"status": "accepted_risk"})
    assert r.status_code == 200 and r.json()["triage"] == "accepted_risk"
    again = client.get(f"/api/scans/{sid}").json()["findings"][0]
    assert again["triage"] == "accepted_risk"
    # invalid status rejected
    bad = client.post(f"/api/findings/{fid}/triage", json={"status": "bogus"})
    assert bad.status_code == 400

    # --- code context ---
    ctx = client.get(f"/api/findings/{fid}/context").json()
    assert ctx["target"] == 1
    assert any("os.system" in ln["text"] for ln in ctx["lines"])
