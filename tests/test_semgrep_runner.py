from pathlib import Path
from app.runners import semgrep


def test_parse_semgrep(tmp_path):
    raw = Path("tests/fixtures/semgrep.json")
    findings = semgrep.parse(raw)
    assert len(findings) == 2
    first = findings[0]
    assert first.tool == "semgrep"
    assert first.severity == "high"
    assert first.file == "app/vuln.py"
    assert first.line == 12
    assert first.cwe == "CWE-95"
    assert findings[1].severity == "info"


def test_registry_contains_semgrep():
    from app.runners.base import RUNNERS
    assert "semgrep" in RUNNERS
    assert RUNNERS["semgrep"].NAME == "semgrep"


def test_run_uses_security_rulesets_only(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd

        class P:
            stdout = "{}"
        return P()

    monkeypatch.setattr(semgrep.subprocess, "run", fake_run)
    semgrep.run(str(tmp_path), tmp_path)
    joined = " ".join(captured["cmd"])
    assert "p/security-audit" in joined
    assert "p/secrets" in joined
    assert "auto" not in captured["cmd"]  # no correctness/style rules
    assert "--no-git-ignore" in captured["cmd"]  # scan uncommitted files too
