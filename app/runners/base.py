from app.runners import semgrep, scc, snyk, sonarqube

RUNNERS = {m.NAME: m for m in (semgrep, scc, snyk, sonarqube)}
