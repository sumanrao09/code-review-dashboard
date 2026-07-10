from app.models import Finding, normalize_severity, SEVERITIES


def test_finding_defaults():
    f = Finding(tool="semgrep", severity="high", rule_id="r1",
                title="t", description="d", file="a.py")
    assert f.line is None
    assert f.verdict is None
    assert f.severity in SEVERITIES


def test_normalize_severity_sonarqube():
    assert normalize_severity("sonarqube", "BLOCKER") == "critical"
    assert normalize_severity("sonarqube", "MAJOR") == "medium"


def test_normalize_severity_semgrep():
    assert normalize_severity("semgrep", "ERROR") == "high"
    assert normalize_severity("semgrep", "WARNING") == "medium"


def test_normalize_severity_snyk_passthrough():
    assert normalize_severity("snyk", "critical") == "critical"


def test_normalize_severity_unknown_defaults_to_info():
    assert normalize_severity("semgrep", "SOMETHING") == "info"
