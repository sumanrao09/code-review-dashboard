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
