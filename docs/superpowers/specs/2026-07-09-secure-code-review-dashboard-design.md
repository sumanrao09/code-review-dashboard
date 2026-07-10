# Secure Code Review Dashboard — Design

**Date:** 2026-07-09
**Status:** Approved

## Overview

A local web dashboard that runs four code-analysis tools against a project in one
go and aggregates their results in a single UI:

- **Semgrep** — SAST (pattern-based static analysis)
- **SonarQube** (Community, via Docker) + **sonar-scanner** — SAST / code quality
- **Snyk** — SAST (`snyk code test`) and dependency/SCA (`snyk test`)
- **SCC** — code metrics (LOC, complexity, language breakdown, COCOMO)

It then adds two workflow modules on top of the raw scan results:

- **AI Validate** — an LLM triages each finding as true/false positive with a
  justification, confidence, impact, and remediation.
- **Report Generation** — produces a standalone HTML vulnerability report from the
  validated findings, matching the fields of the reference template
  (`Vulnerability-Report.HTML`).

Single user, runs on localhost on this Kali machine. No auth, no multi-tenancy.

## User Flow

1. Open `http://localhost:8000`.
2. Enter a **local project path** and select which tools to run (all four by default).
3. Backend preflight-checks the path and tool availability, creates a scan record,
   and runs selected tools in parallel as subprocesses.
4. UI polls scan status and shows a per-tool status chip (pending / running /
   done / failed).
5. Results render in a unified findings view plus per-tool tabs. Scans are saved
   to history and browsable later.
6. Optionally click **Validate with AI** to triage the findings (see AI Validate).
7. Optionally click **Generate Report** to produce a standalone HTML report from
   the validated findings (see Report Generation).

## Architecture

**Stack:** Python 3 + FastAPI backend, SQLite storage, vanilla HTML/JS/CSS
frontend served by FastAPI (no build step). SonarQube Community runs in Docker
via `docker-compose.yml`. Semgrep installed via pip, Snyk CLI via npm binary,
SCC and sonar-scanner as standalone binaries.

```
secure-review-dashboard/
├── app/
│   ├── main.py            # FastAPI app + API routes + static serving
│   ├── db.py              # SQLite schema and queries
│   ├── settings.py        # provider + API key storage (SQLite)
│   ├── scanner.py         # scan orchestration (parallel runners, timeouts)
│   ├── runners/           # one module per tool
│   │   ├── semgrep.py     #   each exposes run() and parse()
│   │   ├── sonarqube.py
│   │   ├── snyk.py
│   │   └── scc.py
│   ├── validator/         # AI Validate module
│   │   ├── service.py     #   orchestration: concurrency, per-scan cap, storage
│   │   └── providers/     #   one module per AI provider (common validate() iface)
│   │       ├── anthropic.py
│   │       └── openai.py
│   ├── report/            # Report Generation module
│   │   ├── generator.py   #   findings + verdicts -> DATA json -> rendered HTML
│   │   └── template.html  #   adapted from Vulnerability-Report.HTML
│   └── static/            # index.html, app.js, style.css (+ settings, validate,
│                          #   generate-report screens)
├── data/                  # SQLite db + per-scan raw tool outputs + generated reports
├── docs/superpowers/specs/
└── docker-compose.yml     # SonarQube server
```

**Runner contract:** each runner module exposes
`run(project_path, workdir) -> raw output file` and
`parse(raw) -> list[Finding]`. Runners are independent; adding a tool means
adding one module. A tool failure marks only that tool as failed — the scan
completes with the remaining tools' results.

## Data Model (SQLite)

- **scans** — id, project path, started/finished timestamps, per-tool status
  and error message.
- **findings** — normalized vulnerability findings (see schema below), including
  AI verdict columns populated by AI Validate.
- **metrics** — SCC output per scan: total LOC, complexity, COCOMO estimate,
  and per-language breakdown (stored as JSON).
- **settings** — key/value store for AI provider choice and API keys (local only).
- **reports** — generated reports linked to a scan: id, scan id, path to the
  HTML file under `data/`, created timestamp, and the metadata form values used.

### Normalized Finding schema

| Field | Notes |
|---|---|
| `tool` | semgrep / sonarqube / snyk |
| `severity` | normalized: critical / high / medium / low / info |
| `rule_id` | tool's rule key |
| `title` | short human-readable summary |
| `description` | full description from the tool |
| `file` | path relative to scanned project |
| `line` | line number (nullable, e.g. dependency findings) |
| `cwe` | CWE id where the tool provides one (nullable) |
| `verdict` | AI Validate: confirmed / partially_true / false_positive / inconclusive (nullable until validated) |
| `confidence` | AI Validate: high / medium / low (nullable) |
| `verdict_note` | AI Validate: justification for the verdict (nullable) |
| `impact_text` | AI Validate: technical impact narrative (nullable) |
| `recommendation` | AI Validate: remediation guidance (nullable) |

AI Validate may also refine `cwe` when the tool did not supply one.

**Severity mapping:** each tool's native scale maps to the normalized one
(e.g. SonarQube BLOCKER→critical, CRITICAL→high, MAJOR→medium, MINOR→low,
INFO→info; Semgrep ERROR→high, WARNING→medium, INFO→info; Snyk uses its own
critical/high/medium/low directly).

**Dedup hint:** findings from different tools sharing file + line + CWE are
visually grouped as "likely duplicate" in the UI. Nothing is auto-deleted.

## Tool Integration Notes

- **Semgrep:** `semgrep scan --config auto --json`. Fully local.
- **SonarQube:** `sonar-scanner` pushes analysis to the local Docker server
  (project key derived per scan); the runner then polls SonarQube's REST API
  (`/api/issues/search`) with a locally generated user token to retrieve issues.
- **Snyk:** `snyk code test --json` for SAST; additionally `snyk test --json`
  when a dependency manifest (package.json, requirements.txt, pom.xml, etc.)
  is present. Requires one-time `snyk auth` with a free account.
- **SCC:** `scc --format json`. Output feeds the metrics panel, not findings.

## AI Validate

Manual, per-scan triage of findings by an LLM. Never runs automatically — you
click **Validate with AI** on a scan's results, so tokens are only spent on
demand.

**Providers (multi-provider):** a **Settings** page stores the provider choice
(Anthropic or OpenAI) and API keys in the SQLite `settings` table (local only,
never hard-coded). `validator/providers/` has one module per provider behind a
common `validate(finding, code_context) -> Verdict` interface — mirrors the
`runners/` pattern, so adding a provider is one file. Anthropic uses the
`anthropic` SDK with `claude-opus-4-8`; OpenAI uses its SDK.

**Per-finding call:** the prompt carries the tool, rule id, severity, file, line,
the finding message, and ±15 lines of source pulled from the scanned project.
The model is asked via **structured outputs** (a JSON schema — no fragile
parsing) to return:

| Verdict field | Values / meaning |
|---|---|
| `verdict` | confirmed / partially_true / false_positive |
| `confidence` | high / medium / low |
| `verdict_note` | justification (why it is real or not) |
| `impact_text` | technical impact narrative |
| `recommendation` | remediation guidance |
| `cwe` | CWE id when derivable |

These map 1:1 onto the report template fields, so validation output flows
straight into Report Generation.

**Execution & cost control:** findings validate concurrently with a bounded
worker pool (default 5) and a per-scan cap; a progress bar shows N/total.
Each finding's raw request/response is saved under the scan workspace for audit.

**Refusals:** on an Anthropic `stop_reason: "refusal"` (security content can
trigger false-positive classifier declines) the finding is marked `inconclusive`
rather than crashing the run. The Anthropic call opts into a server-side fallback
to Opus so a benign refusal is transparently retried.

## Report Generation

Produces a standalone HTML vulnerability report from validated findings, reusing
the reference `Vulnerability-Report.HTML` structure verbatim: a self-contained
single file with an embedded `DATA` JSON blob and client-side rendering, print-to-
PDF ready.

**Generator:** one Jinja2 template (`report/template.html`, adapted from the
reference) emits the same skeleton; `generator.py` injects a freshly built
`DATA.F[]`, `DATA.CWE{}`, and `DATA.LOCS{}` from the scan's findings.

**Field mapping** (normalized finding + AI verdict → template fields):

- `title` ← finding title; `risk` ← normalized severity; `location` / `line` ←
  file + line; `code` ← source snippet; `component` / `category` ← tool + rule
  metadata; `ref` ← rule reference.
- `verdict` / `verdict_note` / `confidence` / `impact_text` / `recommendation` /
  `cwe` ← AI Validate output.
- Metadata grid (client, assessment type, repos in scope, report date) ← a short
  form on the **Generate Report** screen; scanned path and scan date prefilled.
- Severity tiles and the verdict summary line ← computed counts.

**Default filter:** the report includes **confirmed + partially_true** findings
(the "true positives"); a checkbox appends false positives in an appendix.
Reports are saved under `data/` per scan and listed in scan history.

## Dashboard UI

Single page, three views:

1. **New Scan / History (home):** path input, tool checkboxes, Scan button;
   table of past scans (date, project, per-tool status, severity totals);
   click a row to open its results.
2. **Unified results tab (default):** summary cards (findings by severity,
   findings by tool, SCC quick stats) above a sortable/filterable findings
   table (filters: severity, tool, file). Rows expand to full description and
   rule info. Likely-duplicate groups are visually indicated.
3. **Per-tool tabs:** each tool's findings in its native vocabulary plus a link
   to the raw JSON output; the SCC tab shows the metrics and language table.

During a scan, each tool shows a live status chip; failures display the error.

The results page adds a **Validate with AI** button (shows a progress bar and,
once done, verdict/confidence badges and AI notes on each finding) and a
**Generate Report** button (opens the metadata form, then produces the report).
A separate **Settings** page holds the AI provider choice and API keys.

## Error Handling

- **Preflight on submit:** path exists; each selected tool's binary is present;
  SonarQube server reachable; Snyk authenticated. Problems are reported in the
  UI before running; an unavailable tool is skipped with a warning rather than
  blocking the scan.
- **Timeouts:** each tool gets a 15-minute default timeout; a timed-out tool is
  marked failed.
- **Debuggability:** raw stdout/stderr of every tool run is saved in the
  per-scan workspace under `data/`.
- **AI Validate:** missing/invalid API key or provider errors are reported in the
  UI without failing the scan; an individual finding that errors or refuses is
  marked `inconclusive` and validation continues with the rest.

## Testing

- **Unit tests:** each runner's `parse()` tested against captured real output
  fixtures from the actual tools; each provider's response-to-`Verdict` mapping
  tested against captured API responses (including a refusal); the report
  generator tested by rendering fixture findings and asserting the expected
  `DATA` fields and section counts appear.
- **Integration test:** scan a small deliberately-vulnerable sample project
  end-to-end and assert normalized findings appear in the DB and API. AI Validate
  and Report Generation are integration-tested against a stubbed provider (no
  live API calls) to verify verdicts persist and a report renders.

## Out of Scope (YAGNI)

- Authentication / multi-user support
- Git URL or zip upload input (local path only for now)
- Auto-remediation or PR creation
- CI integration
- Automatic (non-manual) AI validation on every scan
- Cloud/remote storage of AI API keys (kept in local SQLite only)
- Editing the report template through the UI
