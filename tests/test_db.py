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


def test_references_roundtrip(tmp_path):
    conn = _conn(tmp_path)
    sid = db.create_scan(conn, "/proj", ["semgrep"])
    refs = [{"title": "OWASP", "url": "https://owasp.org/x"},
            {"title": None, "url": "https://cwe.mitre.org/y"}]
    db.insert_findings(conn, sid, [
        Finding(tool="semgrep", severity="high", rule_id="r", title="t",
                description="d", file="a.py", references=refs),
    ])
    got = db.get_findings(conn, sid)[0]
    assert got.references == refs


def test_triage_default_and_update(tmp_path):
    conn = _conn(tmp_path)
    sid = db.create_scan(conn, "/proj", ["semgrep"])
    db.insert_findings(conn, sid, [
        Finding(tool="semgrep", severity="high", rule_id="r", title="t",
                description="d", file="a.py", line=3),
    ])
    fid = db.get_findings(conn, sid)[0].id
    assert db.get_findings(conn, sid)[0].triage == "open"  # default
    db.update_finding_triage(conn, fid, "fixed")
    assert db.get_findings(conn, sid)[0].triage == "fixed"


def test_migrate_adds_refs_column(tmp_path):
    # A database created before the refs column must gain it on init_db.
    p = tmp_path / "old.db"
    conn = db.connect(p)
    conn.executescript(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "scan_id INTEGER, tool TEXT, severity TEXT, rule_id TEXT, title TEXT, "
        "description TEXT, file TEXT, line INTEGER, cwe TEXT, verdict TEXT, "
        "confidence TEXT, verdict_note TEXT, impact_text TEXT, recommendation TEXT)"
    )
    conn.commit()
    conn.close()

    db.init_db(p)  # should migrate in place, not error
    conn = db.connect(p)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    assert "refs" in cols
    assert "triage" in cols

    # A finding read back from a migrated DB still gets a sane triage default.
    sid = db.create_scan(conn, "/proj", ["semgrep"])
    db.insert_findings(conn, sid, [
        Finding(tool="semgrep", severity="high", rule_id="r", title="t",
                description="d", file="a.py", line=1),
    ])
    assert db.get_findings(conn, sid)[0].triage == "open"


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
