import json
from pathlib import Path

from jinja2 import Environment, select_autoescape

from app import db
from app.config import SCANS_DIR

TEMPLATE_PATH = Path(__file__).parent / "template.html"

_INCLUDED_VERDICTS = {"confirmed", "partially_true"}

# Map generator severity values → template-expected capitalized tokens
_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

# Map generator verdict values → template-expected tokens
_VERDICT_MAP = {
    "confirmed": "CONFIRMED",
    "partially_true": "PARTIALLY TRUE",
    "false_positive": "FALSE POSITIVE",
    "inconclusive": "CONFIRMED (New)",
}


def _to_entry(f) -> dict:
    return {
        "title": f.title,
        "risk": _SEVERITY_MAP.get(f.severity, f.severity),
        "component": f.tool,
        "category": f.rule_id,
        "description": f.description,
        "code": "",
        "impactText": f.impact_text or "",
        "location": f.file,
        "line": f.line,
        "parameter": "",
        "recommendation": f.recommendation or "",
        "ref": "",
        "verdict": _VERDICT_MAP.get(f.verdict, "") if f.verdict else "",
        "verdictNote": f.verdict_note or "",
        "confidence": f.confidence or "",
        "cwe": f.cwe or "",
    }


def build_data(findings: list, meta: dict, include_false_positives: bool) -> dict:
    selected = []
    for f in findings:
        if f.verdict in _INCLUDED_VERDICTS:
            selected.append(f)
        elif include_false_positives and f.verdict in ("false_positive",
                                                       "inconclusive"):
            selected.append(f)
        elif f.verdict is None:
            selected.append(f)  # unvalidated findings still appear
    entries = [_to_entry(f) for f in selected]
    cwe_map = {f.title: f.cwe for f in selected if f.cwe}
    return {"F": entries, "CWE": cwe_map, "LOCS": {}, "VERDICTS": {}}


def render_report(data: dict, meta: dict) -> str:
    env = Environment(autoescape=select_autoescape(["html"]))
    template_src = Path(TEMPLATE_PATH).read_text()
    template = env.from_string(template_src)
    # Serialize data as a script-safe JSON string (break </script> sequences)
    data_json = json.dumps(data).replace("</", "<\\/")
    return template.render(data_json=data_json, meta=meta)


def generate(conn, scan_id: int, meta: dict,
             include_false_positives: bool) -> str:
    findings = db.get_findings(conn, scan_id)
    data = build_data(findings, meta, include_false_positives)
    html = render_report(data, meta)
    workdir = Path(SCANS_DIR) / str(scan_id)
    workdir.mkdir(parents=True, exist_ok=True)
    n = len(db.list_reports(conn, scan_id)) + 1
    out = workdir / f"report-{n}.html"
    out.write_text(html)
    db.create_report(conn, scan_id, str(out), json.dumps(meta))
    return str(out)
