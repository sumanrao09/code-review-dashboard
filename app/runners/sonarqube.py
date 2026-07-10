import json
import os
import subprocess
from pathlib import Path

import httpx

from app.models import Finding, normalize_severity

NAME = "sonarqube"
BINARY = "sonar-scanner"
SONAR_URL = "http://localhost:9000"
SONAR_TOKEN = os.environ.get("SONAR_TOKEN", "admin")  # local dev default; override via env in production use


def _project_key(project_path: str) -> str:
    return "scan-" + Path(project_path).name


def run(project_path: str, workdir: Path) -> Path:
    key = _project_key(project_path)
    subprocess.run(
        [BINARY,
         f"-Dsonar.projectKey={key}",
         f"-Dsonar.sources={project_path}",
         f"-Dsonar.host.url={SONAR_URL}",
         f"-Dsonar.login={SONAR_TOKEN}"],
        capture_output=True, text=True, cwd=project_path,
    )
    out = workdir / "sonar_issues.json"
    resp = httpx.get(
        f"{SONAR_URL}/api/issues/search",
        params={"componentKeys": key, "ps": 500},
        auth=(SONAR_TOKEN, ""), timeout=60,
    )
    out.write_text(resp.text if resp.status_code == 200 else '{"issues": []}')
    return out


def _strip_component(component: str) -> str:
    return component.split(":", 1)[1] if ":" in component else component


def parse(raw_path: Path) -> list:
    data = json.loads(Path(raw_path).read_text() or "{}")
    findings = []
    for i in data.get("issues", []):
        cwes = i.get("cwe", [])
        findings.append(Finding(
            tool=NAME,
            severity=normalize_severity(NAME, i.get("severity", "INFO")),
            rule_id=i.get("rule", ""),
            title=i.get("rule", "sonarqube issue"),
            description=i.get("message", ""),
            file=_strip_component(i.get("component", "")),
            line=i.get("line"),
            cwe=cwes[0] if cwes else None,
        ))
    return findings
