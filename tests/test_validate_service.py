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


def test_validate_finding_updates_only_that_finding(tmp_path):
    conn, sid = _seed(tmp_path)
    target = db.get_findings(conn, sid)[0]

    def fake_provider(prompt, api_key):
        return Verdict("false_positive", "medium", "n", "i", "r", None)

    v = service.validate_finding(conn, target, str(tmp_path),
                                 fake_provider, "key")
    assert v.verdict == "false_positive"
    findings = db.get_findings(conn, sid)
    assert findings[0].verdict == "false_positive"
    assert findings[1].verdict is None  # untouched


def test_provider_error_becomes_inconclusive(tmp_path):
    conn, sid = _seed(tmp_path)

    def boom_provider(prompt, api_key):
        raise RuntimeError("api down")

    service.validate_scan(conn, sid, str(tmp_path), boom_provider, "key")
    findings = db.get_findings(conn, sid)
    assert all(f.verdict == "inconclusive" for f in findings)
    assert "api down" in findings[0].verdict_note
