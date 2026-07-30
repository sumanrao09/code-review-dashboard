"""Tests for the SCC-first profiler and scan-recommendation matrix."""
from app import profiler
from app.models import Metrics


def _metrics(languages, total_code=None, complexity=0, cocomo=0.0):
    total_code = sum(l.get("Code", 0) for l in languages) if total_code is None else total_code
    return Metrics(
        total_lines=sum(l.get("Lines", l.get("Code", 0)) for l in languages),
        total_code=total_code, complexity=complexity,
        cocomo_months=cocomo, languages=languages,
    )


def _recs(analysis_or_profile):
    return {r["tool"]: r for r in profiler._recommend(analysis_or_profile)}


# ---------- size buckets ----------
def test_size_buckets():
    assert profiler.size_bucket(0) == "small"
    assert profiler.size_bucket(999) == "small"
    assert profiler.size_bucket(1_000) == "medium"
    assert profiler.size_bucket(49_999) == "medium"
    assert profiler.size_bucket(50_000) == "large"


def test_is_code_language_excludes_data_formats():
    assert profiler._is_code_language("Python")
    assert profiler._is_code_language("JavaScript")
    assert not profiler._is_code_language("Markdown")
    assert not profiler._is_code_language("JSON")
    assert not profiler._is_code_language("YAML")


# ---------- profile shape ----------
def test_build_profile_primary_language_ignores_docs(tmp_path):
    m = _metrics([
        {"Name": "Markdown", "Code": 5000, "Lines": 5000, "Complexity": 0},
        {"Name": "Python", "Code": 800, "Lines": 1000, "Complexity": 40},
    ])
    prof = profiler.build_profile(str(tmp_path), m)
    assert prof["profiled"] is True
    assert prof["primary_language"] == "Python"          # not Markdown
    assert prof["code_languages"] == ["Python"]
    assert prof["size"] == "medium"                      # 5000 + 800 = 5800 LOC


# ---------- matrix rules ----------
def test_recommend_python_with_manifest(tmp_path):
    prof = {"profiled": True, "size": "medium", "code_languages": ["Python"],
            "num_code_languages": 1, "manifests": ["requirements.txt"],
            "total_code": 12_000}
    recs = _recs(prof)
    assert recs["semgrep"]["recommended"] is True
    assert recs["snyk"]["recommended"] is True
    assert "requirements.txt" in recs["snyk"]["reason"]          # SCA rationale
    assert recs["sonarqube"]["recommended"] is True             # medium size


def test_recommend_small_single_language_makes_sonar_optional():
    prof = {"profiled": True, "size": "small", "code_languages": ["Python"],
            "num_code_languages": 1, "manifests": [], "total_code": 300}
    recs = _recs(prof)
    assert recs["semgrep"]["recommended"] is True
    assert recs["snyk"]["recommended"] is True                  # Snyk Code SAST
    assert "SCA is skipped" in recs["snyk"]["reason"]
    assert recs["sonarqube"]["recommended"] is False            # small + 1 lang


def test_recommend_multilang_small_still_gets_sonar():
    prof = {"profiled": True, "size": "small", "code_languages": ["Go", "Python"],
            "num_code_languages": 2, "manifests": [], "total_code": 400}
    recs = _recs(prof)
    assert recs["sonarqube"]["recommended"] is True             # >=2 languages


def test_recommend_no_code():
    prof = {"profiled": True, "size": "small", "code_languages": [],
            "num_code_languages": 0, "manifests": [], "total_code": 0}
    recs = _recs(prof)
    assert recs["semgrep"]["recommended"] is False
    assert recs["snyk"]["recommended"] is False
    assert recs["sonarqube"]["recommended"] is False


def test_recommend_unprofiled_falls_back_to_defaults():
    prof = {"profiled": False, "size": None, "code_languages": [],
            "num_code_languages": 0, "manifests": ["package.json"], "total_code": 0}
    recs = _recs(prof)
    assert recs["semgrep"]["recommended"] is True               # broad default
    assert recs["snyk"]["recommended"] is True
    assert "package.json" in recs["snyk"]["reason"]             # manifest still used
    assert recs["sonarqube"]["recommended"] is False


# ---------- manifest detection ----------
def test_detect_manifests_shallow_and_skips_heavy_dirs(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    sub = tmp_path / "service"; sub.mkdir()
    (sub / "package.json").write_text("{}", encoding="utf-8")
    nm = tmp_path / "node_modules" / "x"; nm.mkdir(parents=True)
    (nm / "package.json").write_text("{}", encoding="utf-8")   # must be skipped
    found = profiler._detect_manifests(str(tmp_path))
    assert "requirements.txt" in found
    assert "package.json" in found          # from service/, not node_modules/
    assert found == sorted(found)


# ---------- endpoint ----------
def test_analyze_endpoint_with_stubbed_scc(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app

    m = _metrics([{"Name": "Python", "Code": 2000, "Lines": 2500, "Complexity": 80}],
                 complexity=80, cocomo=5.2)
    monkeypatch.setattr(profiler.shutil, "which", lambda _b: "/usr/bin/scc")
    monkeypatch.setattr(profiler.scc_runner, "run", lambda p, w: tmp_path / "scc.json")
    monkeypatch.setattr(profiler.scc_runner, "parse_metrics", lambda raw: m)

    r = TestClient(app).post("/api/analyze", json={"project_path": str(tmp_path)})
    assert r.status_code == 200
    body = r.json()
    assert body["profile"]["primary_language"] == "Python"
    assert body["metrics"]["total_code"] == 2000
    tools = {rec["tool"]: rec for rec in body["recommendations"]}
    assert tools["semgrep"]["recommended"] is True
    assert tools["sonarqube"]["recommended"] is True    # medium (2000 LOC)
