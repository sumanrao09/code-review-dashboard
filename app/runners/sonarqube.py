import json
import shutil
import subprocess
from pathlib import Path

import httpx

from app.models import Finding, normalize_severity

from app.runners.sonar_auth import SONAR_URL, resolve_token

NAME = "sonarqube"
BINARY = "sonar-scanner"


def _project_key(project_path: str) -> str:
    return "scan-" + Path(project_path).name


def _scanner_cmd() -> list:
    """Launcher argv for sonar-scanner.

    On Windows the scanner is a .bat, which CreateProcess can't start by
    bare name — it must go through cmd /c with the resolved path.
    """
    exe = shutil.which(BINARY) or BINARY
    if exe.lower().endswith((".bat", ".cmd")):
        return ["cmd", "/c", exe]
    return [exe]


def run(project_path: str, workdir: Path) -> Path:
    key = _project_key(project_path)
    token = resolve_token()  # env var → stored/auto-provisioned → dev default
    subprocess.run(
        _scanner_cmd() +
        [f"-Dsonar.projectKey={key}",
         f"-Dsonar.sources={project_path}",
         f"-Dsonar.host.url={SONAR_URL}",
         f"-Dsonar.login={token}",
         # Keep scanner scratch files out of the scanned repo — also lets
         # the repo be mounted read-only (Docker mounts /projects ro).
         f"-Dsonar.working.directory={workdir / 'scannerwork'}"],
        capture_output=True, text=True, cwd=project_path,
    )
    out = workdir / "sonar_issues.json"
    resp = httpx.get(
        f"{SONAR_URL}/api/issues/search",
        # Security findings only — leave code smells / maintainability out.
        params={"componentKeys": key, "ps": 500,
                "impactSoftwareQualities": "SECURITY"},
        auth=(token, ""), timeout=60,
    )
    out.write_text(resp.text if resp.status_code == 200 else '{"issues": []}',
                   encoding="utf-8")
    return out


def _strip_component(component: str) -> str:
    return component.split(":", 1)[1] if ":" in component else component


def parse(raw_path: Path) -> list:
    data = json.loads(Path(raw_path).read_text(encoding="utf-8") or "{}")
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
