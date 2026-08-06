import json
import subprocess
from pathlib import Path

from app.models import Finding, make_ref, normalize_severity

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


def _references(metadata: dict, rule_id: str) -> list:
    """Reference links Semgrep attached to the rule (advisories, OWASP, docs)."""
    refs = []
    urls = metadata.get("references") or []
    if isinstance(urls, str):
        urls = [urls]
    for url in urls:
        if url:
            refs.append(make_ref(str(url)))
    # The rule's own page on the Semgrep registry is a reliable extra reference.
    src = metadata.get("source")
    if src:
        refs.append(make_ref(str(src), "Semgrep rule"))
    elif rule_id and "." in rule_id:
        refs.append(make_ref(f"https://semgrep.dev/r/{rule_id}", "Semgrep rule"))
    return refs


def parse(raw_path: Path) -> list:
    data = json.loads(Path(raw_path).read_text(encoding="utf-8") or "{}")
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {})
        rule_id = r.get("check_id", "")
        findings.append(Finding(
            tool=NAME,
            severity=normalize_severity(NAME, extra.get("severity", "INFO")),
            rule_id=rule_id,
            title=rule_id.split(".")[-1] or "semgrep finding",
            description=extra.get("message", ""),
            file=r.get("path", ""),
            line=r.get("start", {}).get("line"),
            cwe=_cwe_id(metadata),
            references=_references(metadata, rule_id),
        ))
    return findings
