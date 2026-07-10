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
