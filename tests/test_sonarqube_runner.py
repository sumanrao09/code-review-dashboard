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
