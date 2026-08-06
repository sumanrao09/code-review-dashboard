import json
from pathlib import Path
from app.runners import snyk


def test_parse_snyk_combined(tmp_path):
    combined = {
        "code": json.loads(Path("tests/fixtures/snyk_code.json").read_text(encoding="utf-8")),
        "deps": json.loads(Path("tests/fixtures/snyk_deps.json").read_text(encoding="utf-8")),
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

    # Code findings carry the rule's documentation link.
    code_urls = [r["url"] for r in code.references]
    assert "https://docs.snyk.io/scan-code/snyk-code/python-sqli" in code_urls

    # Dependency findings carry advisory links + upgrade guidance.
    dep_urls = [r["url"] for r in dep.references]
    assert "https://github.com/advisories/GHSA-xxxx" in dep_urls
    assert any("snyk.io/vuln/SNYK-PYTHON-FLASK-1" in u for u in dep_urls)
    assert dep.recommendation and "2.2.5" in dep.recommendation


def test_run_injects_stored_token(tmp_path, monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured["env"] = kwargs.get("env")

        class P:
            stdout = "{}"
        return P()

    monkeypatch.setattr(snyk.subprocess, "run", fake_run)
    monkeypatch.setattr(snyk.token_store, "resolve",
                        lambda env_var, key: "snyk-tok-123")
    snyk.run(str(tmp_path), tmp_path)
    assert captured["env"]["SNYK_TOKEN"] == "snyk-tok-123"
