# Secure Code Review Dashboard

A local web dashboard that runs four code-analysis tools against a project **in one go**, aggregates their findings into a single UI, lets an LLM triage each finding as a true/false positive, and generates a standalone HTML vulnerability report.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)
![Tests](https://img.shields.io/badge/tests-40%20passing-brightgreen)
![Scope](https://img.shields.io/badge/scope-local%20single--user-lightgrey)

---

## What it does

Point it at a local project path, pick the tools, and it runs them concurrently, then normalizes everything into one findings view:

- **Semgrep** — pattern-based SAST
- **SonarQube** (Community, via Docker) + **sonar-scanner** — SAST / code quality
- **Snyk** — SAST (`snyk code test`) **and** dependency/SCA (`snyk test`)
- **SCC** — code metrics (lines, complexity, language breakdown, COCOMO estimate)

On top of the raw results it adds two workflow modules:

- **AI Validate** — a configurable LLM (Anthropic or OpenAI) reviews each finding with the surrounding source code and returns a verdict (`confirmed` / `partially_true` / `false_positive`), a confidence level, a justification, the technical impact, and a remediation.
- **Report Generation** — produces a self-contained, print-ready HTML vulnerability report from the validated findings.

A tool that fails or isn't installed is skipped/marked failed — the scan still completes with the other tools' results.

## Features

- **One-click multi-tool scan** of a local path, tools run in parallel with a per-tool timeout.
- **Unified findings view**: normalized severity (`critical`/`high`/`medium`/`low`/`info`), sortable/filterable table, per-tool tabs, an SCC metrics panel, severity summary cards, and a "likely duplicate" hint for findings that share file + line + CWE across tools.
- **Scan history** persisted in SQLite and browsable.
- **Manual, on-demand AI validation** — never runs (or spends tokens) unless you click **Validate with AI**. Findings validate concurrently with a bounded worker pool; a provider error or refusal degrades a single finding to `inconclusive` without aborting the batch.
- **HTML report** matching a vulnerability-report template, including confirmed + partially-true findings by default (false positives optionally in an appendix).

## Architecture

Python 3 + **FastAPI** backend serving a **vanilla HTML/JS/CSS** single-page frontend (no build step). **SQLite** for scans, findings, metrics, settings, and reports. Each scanner is an independent runner module implementing a small `run()` + `parse()` contract, so adding a tool is one file; likewise each AI provider is one module behind a common `validate()` interface.

```
secure-review-dashboard/
├── app/
│   ├── main.py                 # FastAPI app, API routes, static serving
│   ├── config.py               # paths, timeouts, concurrency
│   ├── db.py                   # SQLite schema + queries
│   ├── models.py               # Finding / Metrics dataclasses, severity mapping
│   ├── settings.py             # AI provider + API-key storage (local SQLite)
│   ├── scanner.py              # preflight + parallel scan orchestration
│   ├── runners/                # one module per tool (run() + parse())
│   │   ├── semgrep.py
│   │   ├── sonarqube.py
│   │   ├── snyk.py
│   │   └── scc.py
│   ├── validator/              # AI Validate
│   │   ├── base.py             # Verdict, JSON schema, code-context + prompt builders
│   │   ├── service.py          # per-scan orchestration (bounded concurrency)
│   │   └── providers/
│   │       ├── anthropic.py    # claude-opus-4-8 + structured output + refusal fallback
│   │       └── openai.py       # gpt-4o + JSON-schema mode
│   ├── report/
│   │   ├── generator.py        # findings + verdicts -> report HTML
│   │   └── template.html       # self-contained report template
│   └── static/                 # index.html, app.js, style.css
├── tests/                      # pytest suite (40 tests) + fixtures
├── docker-compose.yml          # SonarQube Community server
└── requirements.txt
```

## Requirements

- **Python 3.11+** (tested on 3.13)
- The scanner CLIs you want to use, on your `PATH`:
  - `semgrep`, `scc`, `snyk`, and `sonar-scanner`
- **Docker** (only for the SonarQube server)
- An **Anthropic or OpenAI API key** (only if you want AI Validate)

Missing a tool is fine — the dashboard's preflight warns you and skips it; the rest of the scan still runs.

## Installation

```bash
git clone <your-repo-url> secure-review-dashboard
cd secure-review-dashboard

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Install the scanners (as needed)

| Tool | Install | Notes |
|---|---|---|
| Semgrep | `pip install semgrep` | Fully local. |
| SCC | [github.com/boyter/scc](https://github.com/boyter/scc) (binary release) | Fully local. |
| Snyk | `npm install -g snyk` then `snyk auth` | Needs a free Snyk account for the token. |
| SonarQube | `docker compose up -d sonarqube` | First boot takes ~1–2 min. Requires `sonar-scanner` on your PATH. |

For SonarQube, after the container is up, log in at `http://localhost:9000` (default `admin`/`admin`), create a token, and export it so the runner can read issues:

```bash
export SONAR_TOKEN=<your-sonarqube-token>
```

If unset, the runner falls back to the token value `admin` (dev default).

## Running

```bash
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open **http://localhost:8000**.

1. Enter a **local project path**, tick the tools you want, and click **Scan**.
2. Watch the per-tool status chips; results appear in the unified view + per-tool tabs + SCC metrics.
3. (Optional) Open **Settings**, choose a provider (Anthropic/OpenAI), and paste your API key. Then click **Validate with AI** on a scan to triage its findings.
4. (Optional) Click **Generate Report**, fill in the client/assessment metadata, and a standalone HTML report opens in a new tab.

## Configuration

| What | Where | Default |
|---|---|---|
| Bind address | `uvicorn` args | `127.0.0.1:8000` |
| SQLite database | `data/app.db` | auto-created |
| Per-scan tool workspaces & reports | `data/scans/<id>/` | auto-created |
| Per-tool timeout | `app/config.py` (`TOOL_TIMEOUT_SECONDS`) | 15 minutes |
| AI validation concurrency | `app/config.py` (`VALIDATE_CONCURRENCY`) | 5 |
| SonarQube URL | `app/runners/sonarqube.py` (`SONAR_URL`) | `http://localhost:9000` |
| SonarQube token | `SONAR_TOKEN` env var | `admin` |
| AI provider + API keys | **Settings page** → local SQLite `settings` table | none |
| Anthropic model | `app/validator/providers/anthropic.py` | `claude-opus-4-8` |
| OpenAI model | `app/validator/providers/openai.py` | `gpt-4o` |

API keys are stored **only** in the local SQLite database. The settings API returns them masked as `set`/`unset` — never the raw value.

## API

All endpoints are served from `http://localhost:8000`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Serves the single-page dashboard |
| `GET` | `/api/health` | `{"status": "ok"}` |
| `POST` | `/api/scans` | Start a scan. Body: `{"project_path": str, "tools": [str]}` → `{"scan_id", "warnings"}` (runs in the background) |
| `GET` | `/api/scans` | List scans with per-tool status and severity counts |
| `GET` | `/api/scans/{id}` | Scan detail: findings + metrics + per-tool status |
| `POST` | `/api/scans/{id}/validate` | Run AI validation over the scan's findings (needs a provider + key in Settings) |
| `POST` | `/api/scans/{id}/report` | Generate an HTML report. Body: `{"meta": {...}, "include_false_positives": bool}` → `{"path", "report_id"}` |
| `GET` | `/api/reports/{id}` | Download the generated report HTML |
| `GET` | `/api/settings` | Provider config with keys masked (`set`/`unset`) |
| `POST` | `/api/settings` | Save provider + keys. Body: `{"provider", "anthropic_key", "openai_key"}` (empty values don't overwrite) |

## Testing

```bash
source .venv/bin/activate
pytest -q
```

40 tests: each runner's parser is tested against captured tool-output fixtures, each AI provider's response→verdict mapping is tested (including the refusal path), the report generator is rendered against the real template, and an end-to-end integration test drives scan → validate → report through the real HTTP endpoints with the tools and AI provider stubbed (no live tools or API calls).

## Security & scope notes

- **Local, single-user by design** — the server binds to `127.0.0.1` and has **no authentication**. Don't expose it to a network.
- **Untrusted input**: findings originate from tools scanning code you point them at. The frontend HTML-escapes all finding-derived values, and the report generator uses Jinja autoescaping plus `</script>`-breakout escaping for the embedded findings JSON. Still, treat scanning of untrusted repositories with the usual caution.
- **API keys** live only in the local SQLite database and are never returned in cleartext by the API.
- The `tests/fixtures/vuln_project/` sample contains a deliberately-vulnerable snippet used by the integration test.

## How it was built

Implemented test-first (TDD) task by task, with each task independently reviewed for spec compliance and code quality, plus a final whole-branch review. The design spec and implementation plan live under `docs/superpowers/`.

## License

No license has been chosen yet. Add one (e.g. MIT) before publishing if you intend others to use it.
