# Scan recommendation matrix

The dashboard runs **SCC first** to profile a repo, then applies this decision
matrix to recommend which scanners to run. The logic lives in
[`app/profiler.py`](../app/profiler.py) (`build_profile` + `_recommend`) and is
surfaced in the UI as the "Recommended configuration" step. Recommendations are
**defaults you can override** — every tool stays selectable.

## Signals extracted by SCC (the "profile")

| Signal | Source | Used for |
|---|---|---|
| `code_languages` | SCC language list, minus data/markup/config formats | Whether SAST tools apply; primary language |
| `size` | `total_code` → `small` / `medium` / `large` | Whether to add the heavier SonarQube scan |
| `num_code_languages` | count of code languages | Multi-language → SonarQube |
| `manifests` | shallow (depth ≤ 2) scan for dependency files | Whether Snyk SCA (`snyk test`) is worthwhile |

Size buckets: **small** < 1,000 LOC · **medium** 1,000–50,000 · **large** ≥ 50,000
(`SIZE_SMALL_MAX` / `SIZE_MEDIUM_MAX` in `profiler.py`).

Languages treated as non-code (excluded from `code_languages`): Markdown, JSON,
YAML, TOML, INI, XML, SVG, CSV, Plain Text, License, gitignore, reStructuredText,
CSS/Sass/SCSS/Less, Makefile, CMake, …(`_NON_CODE_LANGS`).

## The matrix

Every recommended configuration is **security-only**: tools are configured to
report vulnerabilities and secrets, never code-quality/style/maintainability
issues.

| Tool | Recommended when | Security-only configuration |
|---|---|---|
| **SCC** | always | Profiler/metrics only — produces no findings. |
| **Semgrep** | any recognised source language present | Runs the `p/security-audit` + `p/secrets` registry rulesets (not `auto`, which mixes in correctness/style rules). |
| **Snyk** | dependency manifest present → SCA + Code; else any source → Code only | Inherently security-only (vulns in code and dependencies). |
| **SonarQube** | source present **and** (`size` ∈ {medium, large} **or** ≥ 2 code languages) | Issues fetched with `impactSoftwareQualities=SECURITY` — vulnerabilities only, no code smells. Needs the Docker server. |

Anything not recommended is shown as **Optional** with a reason (e.g. SonarQube
on a small single-language repo, or Snyk when no code/manifests exist).

## Fallback when SCC is unavailable

If `scc` isn't on `PATH` or fails, the repo can't be profiled. The matrix then
returns broad defaults — Semgrep + Snyk recommended, SonarQube optional — and the
UI notes it's "using defaults". Manifest detection still runs (it doesn't need
SCC), so Snyk's SCA rationale stays accurate.
