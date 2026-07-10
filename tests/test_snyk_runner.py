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
