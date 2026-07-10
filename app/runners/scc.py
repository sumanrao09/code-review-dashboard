import json
import subprocess
from pathlib import Path

from app.models import Metrics

NAME = "scc"
BINARY = "scc"


def run(project_path: str, workdir: Path) -> Path:
    out = workdir / "scc.json"
    proc = subprocess.run(
        [BINARY, "--format", "json", project_path],
        capture_output=True, text=True,
    )
    out.write_text(proc.stdout or "[]")
    return out


def _cocomo_months(total_code: int) -> float:
    # Basic COCOMO (organic): effort = 2.4 * KLOC^1.05 person-months.
    if total_code <= 0:
        return 0.0
    kloc = total_code / 1000.0
    return round(2.4 * (kloc ** 1.05), 2)


def parse_metrics(raw_path: Path) -> Metrics:
    langs = json.loads(Path(raw_path).read_text() or "[]")
    total_code = sum(l.get("Code", 0) for l in langs)
    return Metrics(
        total_lines=sum(l.get("Lines", 0) for l in langs),
        total_code=total_code,
        complexity=sum(l.get("Complexity", 0) for l in langs),
        cocomo_months=_cocomo_months(total_code),
        languages=langs,
    )
