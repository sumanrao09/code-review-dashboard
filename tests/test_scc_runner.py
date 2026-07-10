from pathlib import Path
from app.runners import scc


def test_parse_scc_metrics():
    m = scc.parse_metrics(Path("tests/fixtures/scc.json"))
    assert m.total_code == 140
    assert m.total_lines == 180
    assert m.complexity == 23
    assert len(m.languages) == 2
    assert m.cocomo_months > 0
