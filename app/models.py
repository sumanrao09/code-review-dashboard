from dataclasses import dataclass, field
from typing import Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]
VERDICTS = ["confirmed", "partially_true", "false_positive", "inconclusive"]
# Human triage decision, independent of the AI verdict.
TRIAGE_STATES = ["open", "fixed", "false_positive", "accepted_risk"]

_SEVERITY_MAP = {
    "sonarqube": {"BLOCKER": "critical", "CRITICAL": "high", "MAJOR": "medium",
                  "MINOR": "low", "INFO": "info"},
    "semgrep": {"ERROR": "high", "WARNING": "medium", "INFO": "info"},
    "snyk": {"critical": "critical", "high": "high", "medium": "medium",
             "low": "low"},
}


def normalize_severity(tool: str, raw: str) -> str:
    table = _SEVERITY_MAP.get(tool, {})
    return table.get(raw, table.get(str(raw).upper(), "info"))


@dataclass
class Finding:
    tool: str
    severity: str
    rule_id: str
    title: str
    description: str
    file: str
    line: Optional[int] = None
    cwe: Optional[str] = None
    verdict: Optional[str] = None
    confidence: Optional[str] = None
    verdict_note: Optional[str] = None
    impact_text: Optional[str] = None
    recommendation: Optional[str] = None
    # Reference links the scanner attached to the rule, as {"title", "url"}.
    references: list = field(default_factory=list)
    # Human triage decision (see TRIAGE_STATES), independent of the AI verdict.
    triage: str = "open"
    id: Optional[int] = None
    scan_id: Optional[int] = None


def make_ref(url: str, title: Optional[str] = None) -> dict:
    """Normalize a scanner reference into a {"title", "url"} record."""
    return {"title": title, "url": url}


@dataclass
class Metrics:
    total_lines: int = 0
    total_code: int = 0
    complexity: int = 0
    cocomo_months: float = 0.0
    languages: list = field(default_factory=list)
