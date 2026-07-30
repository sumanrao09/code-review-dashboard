import json
import subprocess
from pathlib import Path

from app.models import Finding, normalize_severity

NAME = "semgrep"
BINARY = "semgrep"

# Security rules only — no correctness/style noise ("auto" mixes those in).
CONFIGS = ["p/security-audit", "p/secrets"]


def run(project_path: str, workdir: Path) -> Path:
    out = workdir / "semgrep.json"
    cmd = [BINARY, "scan"]
    for c in CONFIGS:
        cmd += ["--config", c]
    # A security review must cover uncommitted files too — without this,
    # semgrep silently limits the scan to git-tracked files.
    cmd += ["--no-git-ignore", "--json", project_path]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8",
    )
    out.write_text(proc.stdout or "{}", encoding="utf-8")
    return out


def _cwe_id(metadata: dict) -> str | None:
    cwes = metadata.get("cwe") or []
    if not cwes:
        return None
    first = cwes[0] if isinstance(cwes, list) else cwes
    return str(first).split(":")[0].strip()


def parse(raw_path: Path) -> list:
    data = json.loads(Path(raw_path).read_text(encoding="utf-8") or "{}")
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        findings.append(Finding(
            tool=NAME,
            severity=normalize_severity(NAME, extra.get("severity", "INFO")),
            rule_id=r.get("check_id", ""),
            title=r.get("check_id", "").split(".")[-1] or "semgrep finding",
            description=extra.get("message", ""),
            file=r.get("path", ""),
            line=r.get("start", {}).get("line"),
            cwe=_cwe_id(extra.get("metadata", {})),
        ))
    return findings
