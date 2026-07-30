from pathlib import Path
from app.runners import sonarqube
from app.runners.base import RUNNERS


def test_parse_sonarqube():
    findings = sonarqube.parse(Path("tests/fixtures/sonar_issues.json"))
    assert len(findings) == 2
    crit = findings[0]
    assert crit.tool == "sonarqube"
    assert crit.severity == "critical"
    assert crit.file == "app/os_cmd.py"
    assert crit.line == 8
    assert crit.cwe == "CWE-78"
    assert findings[1].severity == "low"


def test_registry_has_all_four():
    assert set(RUNNERS) == {"semgrep", "scc", "snyk", "sonarqube"}


def test_scanner_cmd_wraps_windows_batch(monkeypatch):
    monkeypatch.setattr(sonarqube.shutil, "which",
                        lambda b: r"C:\x\.venv\Scripts\sonar-scanner.bat")
    assert sonarqube._scanner_cmd() == ["cmd", "/c",
                                        r"C:\x\.venv\Scripts\sonar-scanner.bat"]


def test_scanner_cmd_direct_on_unix(monkeypatch):
    monkeypatch.setattr(sonarqube.shutil, "which",
                        lambda b: "/usr/local/bin/sonar-scanner")
    assert sonarqube._scanner_cmd() == ["/usr/local/bin/sonar-scanner"]


def test_run_queries_security_issues_only(tmp_path, monkeypatch):
    captured = {}

    def fake_sub(cmd, **kwargs):
        captured["cmd"] = cmd

    monkeypatch.setattr(sonarqube.subprocess, "run", fake_sub)
    monkeypatch.setattr(sonarqube, "resolve_token", lambda: "tok")

    class R:
        status_code = 200
        text = '{"issues": []}'

    def fake_get(url, params=None, **kwargs):
        captured["params"] = params
        return R()

    monkeypatch.setattr(sonarqube.httpx, "get", fake_get)
    sonarqube.run(str(tmp_path), tmp_path)
    assert captured["params"]["impactSoftwareQualities"] == "SECURITY"
    # scanner scratch dir stays out of the scanned repo (read-only in Docker)
    assert any("sonar.working.directory" in c for c in captured["cmd"])
