from dataclasses import dataclass
from pathlib import Path

from app.models import Finding


@dataclass
class Verdict:
    verdict: str
    confidence: str
    verdict_note: str
    impact_text: str
    recommendation: str
    cwe: str | None = None


VERDICT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "confidence", "verdict_note", "impact_text",
                 "recommendation", "cwe"],
    "properties": {
        "verdict": {"type": "string",
                    "enum": ["confirmed", "partially_true", "false_positive"]},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "verdict_note": {"type": "string"},
        "impact_text": {"type": "string"},
        "recommendation": {"type": "string"},
        "cwe": {"type": ["string", "null"]},
    },
}


def _safe_source_path(project_path: str, file: str) -> Path | None:
    """Resolve file within project_path, refusing paths that escape the root."""
    if not file:
        return None
    root = Path(project_path).resolve()
    try:
        target = (root / file).resolve()
    except (OSError, ValueError, RuntimeError):
        return None
    if target != root and root not in target.parents:
        return None  # path traversal — outside the scanned project
    return target


def _read_source_lines(project_path: str, file: str) -> list[str]:
    target = _safe_source_path(project_path, file)
    if target is None:
        return []
    try:
        return target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def build_code_context(project_path: str, file: str, line: int | None,
                       radius: int = 15) -> str:
    if not line:
        return ""
    lines = _read_source_lines(project_path, file)
    if not lines:
        return ""
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))


def code_context_window(project_path: str, file: str, line: int | None,
                        radius: int = 8) -> dict:
    """Structured source window for UI display: numbered lines + target line."""
    if not line:
        return {"lines": [], "target": None, "file": file}
    lines = _read_source_lines(project_path, file)
    if not lines:
        return {"lines": [], "target": None, "file": file}
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return {
        "file": file,
        "target": line,
        "lines": [{"num": n, "text": lines[n - 1]} for n in range(start, end + 1)],
    }


def build_prompt(finding: Finding, code_context: str) -> str:
    return (
        "You are a security code reviewer. Decide whether the following "
        "static-analysis finding is a true or false positive, based on the "
        "code context.\n\n"
        f"Tool: {finding.tool}\nRule: {finding.rule_id}\n"
        f"Reported severity: {finding.severity}\n"
        f"Title: {finding.title}\nMessage: {finding.description}\n"
        f"Location: {finding.file}:{finding.line}\n\n"
        f"Code context:\n{code_context or '(source unavailable)'}\n\n"
        "Return your assessment as structured JSON with a verdict "
        "(confirmed / partially_true / false_positive), a confidence level, "
        "a short justification (verdict_note), the technical impact "
        "(impact_text), a remediation (recommendation), and a CWE id if you "
        "can identify one (else null)."
    )
