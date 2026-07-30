"""SCC-first codebase profiling + scan-recommendation matrix.

Flow: given a repo path we run SCC (fast, local) to build a *profile*
(languages, size, complexity, dependency manifests), then apply a decision
matrix that recommends which scanners to run and *why*. The matrix rules are
documented in docs/scan-recommendation-matrix.md and mirrored in _recommend().
"""
import os
import shutil
import tempfile
from dataclasses import asdict
from pathlib import Path

from app.runners import scc as scc_runner

# Size buckets by lines of code.
SIZE_SMALL_MAX = 1_000
SIZE_MEDIUM_MAX = 50_000

# SCC language names that are data/markup/config rather than source we scan.
_NON_CODE_LANGS = {
    "Markdown", "JSON", "JSON5", "YAML", "TOML", "INI", "XML", "SVG", "CSV",
    "TSV", "Plain Text", "Text", "License", "gitignore", "Ignore List",
    "ReStructuredText", "AsciiDoc", "Org", "BibTeX", "CSS", "Sass", "SCSS",
    "LESS", "Less", "Stylus", "EditorConfig", "Properties File", "Diff",
    "Patch", "Makefile", "CMake",
}

# Dependency manifests that make a Snyk SCA (`snyk test`) run worthwhile.
_MANIFEST_FILES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock",
    "poetry.lock", "setup.py", "pom.xml", "build.gradle", "build.gradle.kts",
    "go.mod", "go.sum", "Gemfile", "Gemfile.lock", "composer.json",
    "composer.lock", "Cargo.toml", "Cargo.lock",
}

_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "dist", "build", "target",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "vendor",
    ".idea", ".vscode", "site-packages",
}


def _is_code_language(name: str) -> bool:
    return bool(name) and name not in _NON_CODE_LANGS


def size_bucket(total_code: int) -> str:
    if total_code < SIZE_SMALL_MAX:
        return "small"
    if total_code < SIZE_MEDIUM_MAX:
        return "medium"
    return "large"


def _detect_manifests(project_path: str, max_dirs: int = 4000) -> list:
    """Shallow (depth<=2) walk for dependency manifests, skipping heavy dirs."""
    root = Path(project_path)
    found, seen = set(), 0
    for dirpath, dirnames, filenames in os.walk(root):
        seen += 1
        if seen > max_dirs:
            break
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS
                       and not d.startswith(".")]
        depth = len(Path(dirpath).relative_to(root).parts)
        if depth >= 2:
            dirnames[:] = []
        for f in filenames:
            if f in _MANIFEST_FILES:
                found.add(f)
    return sorted(found)


def build_profile(project_path: str, metrics) -> dict:
    """Turn SCC metrics (or None) + manifest detection into a profile dict."""
    manifests = _detect_manifests(project_path)
    if metrics is None:
        return {
            "profiled": False, "size": None, "primary_language": None,
            "languages": [], "code_languages": [], "num_code_languages": 0,
            "num_languages": 0, "manifests": manifests,
            "total_code": 0, "total_lines": 0, "complexity": 0,
            "cocomo_months": 0.0,
        }

    langs = sorted(metrics.languages, key=lambda l: l.get("Code", 0),
                   reverse=True)
    total = metrics.total_code or 1
    code_langs = [l for l in langs
                  if _is_code_language(l.get("Name", "")) and l.get("Code", 0)]
    primary = (code_langs[0]["Name"] if code_langs
               else (langs[0]["Name"] if langs else None))
    lang_view = [{
        "name": l.get("Name", "?"),
        "code": l.get("Code", 0),
        "lines": l.get("Lines", 0),
        "complexity": l.get("Complexity", 0),
        "pct": round(100 * l.get("Code", 0) / total, 1),
    } for l in langs]

    return {
        "profiled": True,
        "size": size_bucket(metrics.total_code),
        "primary_language": primary,
        "languages": lang_view,
        "code_languages": [l["Name"] for l in code_langs],
        "num_code_languages": len(code_langs),
        "num_languages": len(langs),
        "manifests": manifests,
        "total_code": metrics.total_code,
        "total_lines": metrics.total_lines,
        "complexity": metrics.complexity,
        "cocomo_months": metrics.cocomo_months,
    }


def _recommend(profile: dict) -> list:
    """Decision matrix: profile signals -> per-tool {recommended, reason}."""
    size = profile.get("size")
    code_langs = profile.get("code_languages", [])
    manifests = profile.get("manifests", [])
    n_code = profile.get("num_code_languages", 0)
    loc = profile.get("total_code", 0) or 0
    profiled = profile.get("profiled", False)

    recs = []

    # SCC — the profiler itself; included so the scan record carries metrics.
    recs.append({
        "tool": "scc", "recommended": True,
        "reason": "Code metrics & language profile (already run in this step).",
    })

    if not profiled:
        # Couldn't profile (scc missing/failed) — fall back to broad defaults.
        recs.append({"tool": "semgrep", "recommended": True,
                     "reason": "Security-rule SAST — security-audit + secrets "
                               "rulesets (codebase not profiled)."})
        if manifests:
            recs.append({"tool": "snyk", "recommended": True,
                         "reason": f"Dependency/SCA scan — manifest(s) found: "
                                   f"{', '.join(manifests)}. Also Snyk Code SAST."})
        else:
            recs.append({"tool": "snyk", "recommended": True,
                         "reason": "Snyk Code SAST (codebase not profiled)."})
        recs.append({"tool": "sonarqube", "recommended": False,
                     "reason": "Optional — enable if the SonarQube server is running."})
        return recs

    # Semgrep — security-rule SAST; worthwhile wherever there is source code.
    if code_langs:
        recs.append({"tool": "semgrep", "recommended": True,
                     "reason": f"Security-rule SAST (security-audit + secrets "
                               f"rulesets) covering your source "
                               f"({', '.join(code_langs[:3])}"
                               f"{', …' if n_code > 3 else ''})."})
    else:
        recs.append({"tool": "semgrep", "recommended": False,
                     "reason": "No recognised source languages detected."})

    # Snyk — SCA if manifests present, otherwise Snyk Code SAST.
    if manifests:
        recs.append({"tool": "snyk", "recommended": True,
                     "reason": f"Dependency/SCA scan — manifest(s) found: "
                               f"{', '.join(manifests)}. Also runs Snyk Code SAST."})
    elif code_langs:
        recs.append({"tool": "snyk", "recommended": True,
                     "reason": "Snyk Code SAST (no dependency manifest found, "
                               "so SCA is skipped)."})
    else:
        recs.append({"tool": "snyk", "recommended": False,
                     "reason": "No source code or dependency manifests detected."})

    # SonarQube — heavier + needs Docker; reserve for larger/multi-language work.
    if code_langs and (size in ("medium", "large") or n_code >= 2):
        recs.append({"tool": "sonarqube", "recommended": True,
                     "reason": f"Deep SAST, security vulnerabilities only — "
                               f"suited to this {size} codebase "
                               f"({loc:,} LOC, {n_code} language"
                               f"{'s' if n_code != 1 else ''}). Needs the Docker server."})
    elif code_langs:
        recs.append({"tool": "sonarqube", "recommended": False,
                     "reason": "Optional — small single-language codebase; "
                               "SonarQube's Docker overhead may not be worth it."})
    else:
        recs.append({"tool": "sonarqube", "recommended": False,
                     "reason": "No source code detected."})

    return recs


def analyze(project_path: str) -> dict:
    """Run SCC, build the profile, and apply the recommendation matrix."""
    warnings = []
    if not Path(project_path).exists():
        return {"metrics": None, "profile": None, "recommendations": [],
                "warnings": [f"Project path does not exist: {project_path}"]}

    metrics = None
    if shutil.which(scc_runner.BINARY) is None:
        warnings.append("scc not found on PATH — cannot profile the codebase; "
                        "showing default recommendations.")
    else:
        tmp = Path(tempfile.mkdtemp(prefix="scc-analyze-"))
        try:
            raw = scc_runner.run(project_path, tmp)
            metrics = scc_runner.parse_metrics(raw)
        except Exception as exc:  # profiling must not hard-fail the request
            warnings.append(f"scc failed: {exc}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    profile = build_profile(project_path, metrics)
    recommendations = _recommend(profile)
    return {
        "metrics": asdict(metrics) if metrics else None,
        "profile": profile,
        "recommendations": recommendations,
        "warnings": warnings,
    }
