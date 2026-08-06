from app.validator import base
from app.models import Finding


def test_build_code_context(tmp_path):
    src = tmp_path / "a.py"
    src.write_text("\n".join(f"line{i}" for i in range(1, 41)))
    ctx = base.build_code_context(str(tmp_path), "a.py", 20, radius=2)
    assert "line18" in ctx and "line22" in ctx
    assert "line10" not in ctx
    assert "20:" in ctx  # numbered


def test_build_code_context_missing_file(tmp_path):
    assert base.build_code_context(str(tmp_path), "nope.py", 5) == ""


def test_code_context_rejects_path_traversal(tmp_path):
    # A finding path that escapes the project root must not read outside it.
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.py").write_text("x = 1\n")
    assert base.build_code_context(str(proj), "../secret.txt", 1) == ""
    assert base._safe_source_path(str(proj), "../secret.txt") is None


def test_code_context_window_structured(tmp_path):
    src = tmp_path / "a.py"
    src.write_text("\n".join(f"line{i}" for i in range(1, 41)))
    win = base.code_context_window(str(tmp_path), "a.py", 20, radius=3)
    assert win["target"] == 20
    nums = [ln["num"] for ln in win["lines"]]
    assert nums == [17, 18, 19, 20, 21, 22, 23]
    assert win["lines"][3]["text"] == "line20"


def test_code_context_window_no_line(tmp_path):
    win = base.code_context_window(str(tmp_path), "a.py", None)
    assert win["lines"] == [] and win["target"] is None


def test_build_prompt_mentions_finding(tmp_path):
    f = Finding(tool="semgrep", severity="high", rule_id="r1",
                title="SQLi", description="bad", file="a.py", line=3)
    p = base.build_prompt(f, "3: q = 'SELECT ' + x")
    assert "SQLi" in p and "a.py" in p and "SELECT" in p


def test_schema_shape():
    props = base.VERDICT_SCHEMA["properties"]
    assert set(["verdict", "confidence", "verdict_note", "impact_text",
                "recommendation", "cwe"]).issubset(props)
    assert props["verdict"]["enum"] == ["confirmed", "partially_true",
                                        "false_positive"]
