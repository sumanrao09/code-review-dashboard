from dataclasses import dataclass, field
from typing import Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]
VERDICTS = ["confirmed", "partially_true", "false_positive", "inconclusive"]

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
    id: Optional[int] = None
    scan_id: Optional[int] = None


@dataclass
class Metrics:
    total_lines: int = 0
    total_code: int = 0
    complexity: int = 0
    cocomo_months: float = 0.0
    languages: list = field(default_factory=list)
