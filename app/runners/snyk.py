import json
import os
import subprocess
from pathlib import Path

from app import token_store
from app.models import Finding, normalize_severity

NAME = "snyk"
BINARY = "snyk"

_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low",
                      "info": "info"}
_MANIFESTS = ["package.json", "requirements.txt", "pom.xml", "build.gradle",
              "go.mod", "Gemfile"]


def _env() -> dict:
    """Subprocess env with the Snyk token injected (Settings or SNYK_TOKEN)."""
    env = os.environ.copy()
    tok = token_store.resolve("SNYK_TOKEN", "snyk_token")
    if tok:
        env["SNYK_TOKEN"] = tok
    return env


def _json_cmd(args, cwd) -> dict:
    proc = subprocess.run(args, capture_output=True, text=True,
                          encoding="utf-8", cwd=cwd, env=_env())
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {}


def run(project_path: str, workdir: Path) -> Path:
    out = workdir / "snyk.json"
    code = _json_cmd([BINARY, "code", "test", "--json", project_path],
                     project_path)
    deps = {}
    if any((Path(project_path) / m).exists() for m in _MANIFESTS):
        deps = _json_cmd([BINARY, "test", "--json"], project_path)
    out.write_text(json.dumps({"code": code, "deps": deps}), encoding="utf-8")
    return out


def _parse_code(sarif: dict) -> list:
    findings = []
    for run_obj in sarif.get("runs", []):
        for r in run_obj.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            findings.append(Finding(
                tool=NAME,
                severity=_LEVEL_TO_SEVERITY.get(r.get("level", "warning"),
                                                "medium"),
                rule_id=r.get("ruleId", ""),
                title=r.get("ruleId", "snyk code"),
                description=r.get("message", {}).get("text", ""),
                file=loc.get("artifactLocation", {}).get("uri", ""),
                line=loc.get("region", {}).get("startLine"),
            ))
    return findings


def _parse_deps(deps: dict) -> list:
    findings = []
    for v in deps.get("vulnerabilities", []):
        cwes = (v.get("identifiers", {}) or {}).get("CWE", [])
        findings.append(Finding(
            tool=NAME,
            severity=normalize_severity(NAME, v.get("severity", "low")),
            rule_id=v.get("id", ""),
            title=f"{v.get('title', 'Dependency vulnerability')} "
                  f"({v.get('packageName', '')})",
            description=v.get("title", ""),
            file=v.get("packageName", ""),
            line=None,
            cwe=cwes[0] if cwes else None,
        ))
    return findings


def parse(raw_path: Path) -> list:
    data = json.loads(Path(raw_path).read_text(encoding="utf-8") or "{}")
    return _parse_code(data.get("code", {})) + _parse_deps(data.get("deps", {}))
