"use strict";

/* ============================================================
   State
   ============================================================ */
let currentScan = null;
let currentTab = "unified";
let pollTimer = null;

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/* ============================================================
   Helpers
   ============================================================ */
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    const text = await r.text();
    let msg = text || r.statusText;
    try { msg = JSON.parse(text).detail || msg; } catch (_) { /* raw text */ }
    const err = new Error(msg);
    err.status = r.status;
    throw err;
  }
  return r.json();
}

function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const $ = (id) => document.getElementById(id);

function sevPill(s) {
  return `<span class="pill sev-${escapeHtml(s)}"><span class="pill-dot"></span>${escapeHtml(s)}</span>`;
}

let toastTimer = null;
function toast(msg, kind = "info") {
  const el = $("toast");
  el.className = `toast ${kind}`;
  el.innerHTML = `<span class="toast-dot"></span><span>${escapeHtml(msg)}</span>`;
  el.hidden = false;
  requestAnimationFrame(() => el.classList.add("show"));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => { el.hidden = true; }, 220);
  }, 3200);
}

function fmtDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d)) return iso.slice(0, 19).replace("T", " ");
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

/* ============================================================
   Theme
   ============================================================ */
function initTheme() {
  const saved = localStorage.getItem("theme");
  const theme = saved || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  document.documentElement.setAttribute("data-theme", theme);
}
$("theme-toggle").onclick = () => {
  const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("theme", next);
};

/* ============================================================
   Modals
   ============================================================ */
function openModal(id) { $(id).hidden = false; }
function closeModal(id) { $(id).hidden = true; }
document.querySelectorAll("[data-close]").forEach((el) => {
  el.onclick = () => closeModal(el.dataset.close);
});
document.querySelectorAll(".modal-overlay").forEach((ov) => {
  ov.addEventListener("click", (e) => { if (e.target === ov) ov.hidden = true; });
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") document.querySelectorAll(".modal-overlay").forEach((m) => (m.hidden = true));
});

/* ============================================================
   History
   ============================================================ */
async function loadHistory() {
  const scans = await api("/api/scans");
  const body = $("history-body");
  if (!scans.length) {
    body.innerHTML = emptyState("No scans yet", "Run your first scan above to see it here.");
    return;
  }
  const rows = scans.map((s) => {
    const c = s.severity_counts || {};
    const running = !s.finished_at;
    const status = running
      ? `<span class="status-pill running"><span class="spinner"></span>Running</span>`
      : `<span class="status-pill done"><span class="dot"></span>Done</span>`;
    return `<tr data-id="${s.id}">
      <td class="hist-id">#${s.id}</td>
      <td><div class="hist-path" title="${escapeHtml(s.project_path)}">${escapeHtml(s.project_path)}</div></td>
      <td>${escapeHtml(fmtDate(s.started_at))}</td>
      <td>${status}</td>
      <td>${sevMini(c)}</td>
    </tr>`;
  }).join("");
  body.innerHTML = `<table class="history">
    <thead><tr><th>Scan</th><th>Project</th><th>Started</th><th>Status</th><th>Findings</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
  body.querySelectorAll("tr[data-id]").forEach((tr) => {
    tr.onclick = () => openResults(Number(tr.dataset.id));
  });
}

function sevMini(c) {
  return `<div class="sev-mini">` + ["critical", "high", "medium", "low"].map((s) => {
    const n = c[s] || 0;
    return `<span class="sev-count ${n ? "" : "zero"}" title="${s}"><span class="sq ${s}"></span>${n}</span>`;
  }).join("") + `</div>`;
}

function emptyState(title, msg) {
  return `<div class="empty">
    <svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="1.6"
         stroke-linecap="round" stroke-linejoin="round">
      <path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-7l-2-2H5a2 2 0 0 0-2 2z"></path>
    </svg>
    <h4>${escapeHtml(title)}</h4><p>${escapeHtml(msg)}</p></div>`;
}

/* ============================================================
   Run scan + poll
   ============================================================ */
async function runScan() {
  const path = $("project-path").value.trim();
  if (!path) { toast("Enter a project path first", "error"); return; }
  const tools = [...document.querySelectorAll("#tool-checks input:checked")].map((c) => c.value);
  if (!tools.length) { toast("Select at least one tool", "error"); return; }

  const btn = $("run-scan");
  btn.disabled = true;
  try {
    const res = await api("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project_path: path, tools }),
    });
    renderWarnings(res.warnings);
    toast(`Scan #${res.scan_id} started`, "ok");
    if (pollTimer) clearTimeout(pollTimer);
    pollScan(res.scan_id);
  } catch (e) {
    toast("Failed to start scan: " + e.message, "error");
  } finally {
    btn.disabled = false;
  }
}

function renderWarnings(warnings) {
  $("warnings").innerHTML = (warnings || []).map((w) =>
    `<div class="warn"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"
       stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
       <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
       <path d="M12 9v4M12 17h.01"></path></svg><span>${escapeHtml(w)}</span></div>`).join("");
}

/* ============================================================
   Step 1 — Analyze (SCC profile + recommendation matrix)
   ============================================================ */
const LANG_PALETTE = ["#2563eb", "#7c3aed", "#0891b2", "#16a34a", "#d97706", "#dc2626", "#64748b"];
const TOOL_LABELS = { semgrep: "Semgrep", sonarqube: "SonarQube", snyk: "Snyk", scc: "SCC" };
const TOOL_ORDER = ["semgrep", "snyk", "sonarqube", "scc"];

async function analyzeCodebase() {
  const path = $("project-path").value.trim();
  if (!path) { toast("Enter a project path first", "error"); return; }
  const btn = $("analyze-btn");
  const orig = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span><span>Analyzing…</span>`;
  try {
    const data = await api("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project_path: path }),
    });
    renderWarnings(data.warnings);
    renderAnalysis(data);
    $("analysis").hidden = false;
    $("analysis").scrollIntoView({ behavior: "smooth", block: "nearest" });
    toast(data.profile && data.profile.profiled ? "Codebase profiled" : "Analyzed (using defaults)", "ok");
  } catch (e) {
    if (e.status === 404) {
      renderWarnings(["Analyze endpoint not found — the running server is an older build. "
        + "Stop it (Ctrl+C) and restart uvicorn, then reload this page."]);
      toast("Server is out of date — restart uvicorn", "error");
    } else {
      renderWarnings(["Analyze failed: " + (e.message || String(e))]);
      toast("Analyze failed", "error");
    }
  } finally {
    btn.disabled = false;
    btn.innerHTML = orig;
  }
}

function renderAnalysis(data) {
  const p = data.profile, m = data.metrics;
  const badge = $("size-badge");
  if (p && p.size) { badge.className = `size-badge ${p.size}`; badge.textContent = `${p.size} codebase`; }
  else { badge.textContent = ""; }
  renderInsightTiles(p, m);
  renderLangBreakdown(p);
  renderManifests(p);
  renderToolMatrix(data.recommendations);
}

function renderInsightTiles(p, m) {
  const el = $("insight-tiles");
  if (!p || !p.profiled || !m) {
    el.innerHTML = `<div class="stat text"><span class="stat-accent"></span>
      <div class="stat-num sm">Not profiled</div>
      <div class="stat-label">SCC unavailable — using defaults</div></div>`;
    return;
  }
  const tiles = [
    { cls: "text", num: p.primary_language || "—", label: "Primary language" },
    { cls: "metric", num: Number(m.total_code).toLocaleString(), label: "Lines of code" },
    { cls: "metric", num: p.num_languages, label: "Languages" },
    { cls: "metric", num: Number(m.complexity).toLocaleString(), label: "Complexity" },
    { cls: "metric", num: Number(m.cocomo_months).toFixed(1), label: "COCOMO months" },
  ];
  el.innerHTML = tiles.map((t) =>
    `<div class="stat ${t.cls}"><span class="stat-accent"></span>
      <div class="stat-num ${t.cls === "text" ? "sm" : ""}">${escapeHtml(String(t.num))}</div>
      <div class="stat-label">${t.label}</div></div>`).join("");
}

function renderLangBreakdown(p) {
  const el = $("lang-breakdown");
  if (!p || !p.languages || !p.languages.length) { el.innerHTML = ""; return; }
  const langs = p.languages.slice(0, 7);
  const color = (i) => LANG_PALETTE[i % LANG_PALETTE.length];
  const bar = langs.map((l, i) =>
    `<span class="lang-seg" style="width:${l.pct}%;background:${color(i)}" title="${escapeHtml(l.name)} · ${l.pct}%"></span>`).join("");
  const legend = langs.map((l, i) =>
    `<span class="lang-leg"><span class="lang-swatch" style="background:${color(i)}"></span>${escapeHtml(l.name)} <b>${l.pct}%</b></span>`).join("");
  const more = p.languages.length > 7 ? `<span class="lang-leg muted">+${p.languages.length - 7} more</span>` : "";
  el.innerHTML = `<div class="lang-bar">${bar}</div><div class="lang-legend">${legend}${more}</div>`;
}

function renderManifests(p) {
  const el = $("manifests");
  if (!p) { el.innerHTML = ""; return; }
  const label = `<span class="manifests-label">Dependency manifests</span>`;
  el.innerHTML = (p.manifests && p.manifests.length)
    ? label + p.manifests.map((f) => `<span class="manifest-chip">${escapeHtml(f)}</span>`).join("")
    : label + `<span class="manifest-none">none found — SCA scan will be skipped</span>`;
}

function renderToolMatrix(recs) {
  const el = $("tool-checks");
  const byTool = {};
  (recs || []).forEach((r) => { byTool[r.tool] = r; });
  const ordered = TOOL_ORDER.filter((t) => byTool[t]).map((t) => byTool[t]);
  el.innerHTML = ordered.map((r) => {
    const badge = r.recommended
      ? `<span class="rec-badge yes">Recommended</span>`
      : `<span class="rec-badge no">Optional</span>`;
    return `<label class="tool-row ${r.recommended ? "rec" : ""}">
      <input type="checkbox" value="${escapeHtml(r.tool)}" ${r.recommended ? "checked" : ""}>
      <span class="tool-row-check"></span>
      <span class="tool-row-body">
        <span class="tool-row-top"><span class="tool-row-name">${escapeHtml(TOOL_LABELS[r.tool] || r.tool)}</span>${badge}</span>
        <span class="tool-row-reason">${escapeHtml(r.reason)}</span>
      </span></label>`;
  }).join("");
}

async function pollScan(id) {
  let s;
  try {
    s = await api(`/api/scans/${id}`);
  } catch (e) {
    return;
  }
  await loadHistory();
  renderResults(s);
  if (!s.finished_at) {
    pollTimer = setTimeout(() => pollScan(id), 1500);
  } else {
    toast(`Scan #${id} complete`, "ok");
  }
}

/* ============================================================
   Results
   ============================================================ */
async function openResults(id, scroll = true) {
  if (pollTimer) clearTimeout(pollTimer);
  try {
    const s = await api(`/api/scans/${id}`);
    renderResults(s);
    if (!s.finished_at) pollTimer = setTimeout(() => pollScan(id), 1500);
    if (scroll) $("results").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    toast("Could not open scan: " + e.message, "error");
  }
}

function renderResults(scan) {
  currentScan = scan;
  $("results").hidden = false;
  $("result-id").textContent = scan.id;

  const running = !scan.finished_at;
  $("result-status").className = "status-pill " + (running ? "running" : "done");
  $("result-status").innerHTML = running
    ? `<span class="spinner"></span>Running`
    : `<span class="dot"></span>Done`;

  $("result-meta").innerHTML =
    `<span class="mono">${escapeHtml(scan.project_path)}</span>
     <span>Started ${escapeHtml(fmtDate(scan.started_at))}</span>`;

  renderToolChips(scan.tool_status);
  renderSummary();
  renderFindings(currentTab);
  $("validate-progress").textContent = "";
  $("validate-progress").className = "inline-note";
}

function renderToolChips(status) {
  const icon = (st) => st === "running" ? `<span class="spinner"></span>` : `<span class="dot"></span>`;
  $("tool-chips").innerHTML = Object.entries(status || {}).map(([t, v]) => {
    const st = v.status || "pending";
    const err = v.error ? ` — ${escapeHtml(v.error)}` : "";
    return `<span class="status-chip ${escapeHtml(st)}" title="${escapeHtml(t)}: ${escapeHtml(st)}${err}">
      ${icon(st)}<span class="chip-name">${escapeHtml(t)}</span><span>${escapeHtml(st)}</span></span>`;
  }).join("");
}

function renderSummary() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  currentScan.findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  const activeSev = $("f-sev").value;

  let html = SEV_ORDER.map((s) =>
    `<div class="stat ${s} clickable ${activeSev === s ? "active" : ""}" data-sev="${s}">
       <span class="stat-accent"></span>
       <div class="stat-num">${counts[s]}</div>
       <div class="stat-label">${s}</div>
     </div>`).join("");

  const m = currentScan.metrics;
  if (m) {
    html += `<div class="stat metric"><span class="stat-accent"></span>
      <div class="stat-num">${Number(m.total_code).toLocaleString()}</div>
      <div class="stat-label">Lines of code</div></div>`;
  }
  $("summary-cards").innerHTML = html;

  $("summary-cards").querySelectorAll(".stat[data-sev]").forEach((el) => {
    el.onclick = () => {
      const sev = el.dataset.sev;
      $("f-sev").value = $("f-sev").value === sev ? "" : sev;
      setTab("unified");
    };
  });
}

/* ============================================================
   Findings table
   ============================================================ */
function renderFindings(tab) {
  currentTab = tab;
  const panel = $("findings-panel");
  $("filters").style.visibility = tab === "scc" ? "hidden" : "visible";

  if (tab === "scc") { renderMetrics(panel); return; }

  const sevFilter = $("f-sev").value;
  const toolFilter = $("f-tool").value;

  // duplicate hint: findings across tools sharing file+line+cwe
  const dupKeys = {};
  currentScan.findings.forEach((f) => {
    const k = `${f.file}|${f.line}|${f.cwe || ""}`;
    dupKeys[k] = (dupKeys[k] || 0) + 1;
  });

  let items = currentScan.findings.slice();
  if (tab !== "unified") items = items.filter((f) => f.tool === tab);
  if (sevFilter) items = items.filter((f) => f.severity === sevFilter);
  if (toolFilter) items = items.filter((f) => f.tool === toolFilter);
  items.sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));

  if (!items.length) {
    panel.innerHTML = emptyState("No findings", "Nothing matches the current tab and filters.");
    return;
  }

  // Remember which rows are expanded so a re-render doesn't collapse them.
  const openFids = new Set([...panel.querySelectorAll("tr.frow.open")]
    .map((tr) => Number(tr.dataset.fid)));

  const rows = items.map((f, i) => {
    const k = `${f.file}|${f.line}|${f.cwe || ""}`;
    const dup = f.cwe && dupKeys[k] > 1
      ? `<span class="dup" title="Likely duplicate across tools">⧉</span>` : "";
    const loc = `${escapeHtml(f.file)}${f.line != null ? ":" + f.line : ""}`;
    const verdict = f.verdict
      ? `<span class="verdict verdict-${escapeHtml(f.verdict)}">${escapeHtml(f.verdict.replace(/_/g, " "))}</span>`
      : `<span class="verdict verdict-none">—</span>`;
    const isOpen = openFids.has(f.id);
    return `<tr class="frow ${isOpen ? "open" : ""}" data-i="${i}" data-fid="${f.id}">
        <td><span class="chev">›</span></td>
        <td>${sevPill(f.severity)}</td>
        <td class="col-tool"><span class="tool-badge">${escapeHtml(f.tool)}</span></td>
        <td class="f-loc">${loc} ${dup}</td>
        <td class="f-title">${escapeHtml(f.title)}${f.rule_id ? `<span class="rule">${escapeHtml(f.rule_id)}</span>` : ""}</td>
        <td class="col-verdict">${verdict}</td>
        <td class="f-act">
          <button class="btn-mini validate-one" data-fid="${f.id}"
                  title="Send this finding to the configured AI for validation" type="button">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor"
                 stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 2 4 5v6c0 5 3.4 7.4 8 9 4.6-1.6 8-4 8-9V5z"></path>
              <path d="m9 12 2 2 4-4"></path></svg>
            <span>${f.verdict ? "Re-validate" : "Validate"}</span>
          </button>
        </td>
      </tr>
      <tr class="fdetail" data-detail="${i}" ${isOpen ? "" : "hidden"}><td colspan="7">${detailHtml(f)}</td></tr>`;
  }).join("");

  panel.innerHTML = `<table class="findings">
    <thead><tr><th></th><th>Severity</th><th class="col-tool">Tool</th><th>Location</th><th>Finding</th><th class="col-verdict">AI verdict</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table>`;

  panel.querySelectorAll("tr.frow").forEach((tr) => {
    tr.onclick = () => {
      const d = panel.querySelector(`tr[data-detail="${tr.dataset.i}"]`);
      const open = !d.hidden;
      d.hidden = open;
      tr.classList.toggle("open", !open);
    };
  });
  panel.querySelectorAll(".validate-one").forEach((b) => {
    b.onclick = (e) => {
      e.stopPropagation();          // don't toggle the detail row
      validateOne(Number(b.dataset.fid), b);
    };
  });
}

async function validateOne(fid, btn) {
  btn.disabled = true;
  const orig = btn.innerHTML;
  btn.innerHTML = `<span class="spinner"></span><span>Validating…</span>`;
  try {
    const updated = await api(`/api/findings/${fid}/validate`, { method: "POST" });
    const idx = currentScan.findings.findIndex((f) => f.id === updated.id);
    if (idx !== -1) currentScan.findings[idx] = updated;
    renderFindings(currentTab);     // re-render keeps expanded rows open
    toast(`AI verdict: ${(updated.verdict || "inconclusive").replace(/_/g, " ")}`,
          updated.verdict === "false_positive" ? "info" : "ok");
  } catch (e) {
    toast("Validation failed: " + e.message, "error");
    btn.innerHTML = orig;
    btn.disabled = false;
  }
}

function detailHtml(f) {
  const tags = [];
  if (f.cwe) tags.push(`CWE: ${escapeHtml(f.cwe)}`);
  if (f.rule_id) tags.push(`Rule: ${escapeHtml(f.rule_id)}`);
  if (f.confidence) tags.push(`Confidence: ${escapeHtml(f.confidence)}`);
  const tagRow = tags.length
    ? `<div class="meta-tags">${tags.map((t) => `<span class="meta-tag">${t}</span>`).join("")}</div>` : "";

  const desc = f.description
    ? `<div class="detail-block"><div class="detail-label">Description</div>
        <div class="detail-text">${escapeHtml(f.description)}</div></div>` : "";

  let ai = "";
  if (f.verdict) {
    const block = (label, val) => val
      ? `<div class="detail-block"><div class="detail-label">${label}</div>
          <div class="detail-text">${escapeHtml(val)}</div></div>` : "";
    ai = `<div class="ai-panel">
      <div class="ai-panel-head">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 7.4 8 9 4.6-1.6 8-4 8-9V5z"></path>
          <path d="m9 12 2 2 4-4"></path></svg>
        AI verdict:
        <span class="verdict verdict-${escapeHtml(f.verdict)}">${escapeHtml(f.verdict.replace(/_/g, " "))}</span>
      </div>
      <div class="detail-grid">
        ${block("Justification", f.verdict_note)}
        ${block("Impact", f.impact_text)}
        ${block("Remediation", f.recommendation)}
      </div></div>`;
  }

  return `<div class="fdetail-inner">${tagRow}${desc}${ai || (desc ? "" : `<div class="detail-text" style="color:var(--text-muted)">No additional detail. Run <b>Validate with AI</b> for an assessment.</div>`)}</div>`;
}

function renderMetrics(panel) {
  const m = currentScan.metrics;
  if (!m) { panel.innerHTML = emptyState("No metrics", "SCC did not produce metrics for this scan."); return; }
  const tiles = [
    ["Lines of code", Number(m.total_code).toLocaleString()],
    ["Total lines", Number(m.total_lines).toLocaleString()],
    ["Complexity", Number(m.complexity).toLocaleString()],
    ["COCOMO (months)", Number(m.cocomo_months).toFixed(1)],
  ].map(([label, val]) =>
    `<div class="stat metric"><span class="stat-accent"></span>
      <div class="stat-num">${val}</div><div class="stat-label">${label}</div></div>`).join("");

  const langs = (m.languages || []).map((l) =>
    `<tr><td>${escapeHtml(l.Name)}</td>
      <td class="num">${Number(l.Code || 0).toLocaleString()}</td>
      <td class="num">${Number(l.Lines || l.Code || 0).toLocaleString()}</td>
      <td class="num">${Number(l.Complexity || 0).toLocaleString()}</td></tr>`).join("");

  panel.innerHTML = `<div class="metrics-wrap">
    <div class="stat-grid">${tiles}</div>
    ${langs ? `<table class="lang"><thead><tr><th>Language</th><th class="num">Code</th><th class="num">Lines</th><th class="num">Complexity</th></tr></thead><tbody>${langs}</tbody></table>` : ""}
  </div>`;
}

/* ============================================================
   Tabs + filters
   ============================================================ */
function setTab(tab) {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === tab));
  renderSummary();
  renderFindings(tab);
}
document.querySelectorAll(".tab").forEach((b) => (b.onclick = () => setTab(b.dataset.tab)));
["f-sev", "f-tool"].forEach((id) => ($(id).onchange = () => { renderSummary(); renderFindings(currentTab); }));

SEV_ORDER.forEach((s) => { $("f-sev").innerHTML += `<option value="${s}">${s}</option>`; });
["semgrep", "sonarqube", "snyk"].forEach((t) => { $("f-tool").innerHTML += `<option value="${t}">${t}</option>`; });

/* ============================================================
   Settings
   ============================================================ */
const KEYED_PROVIDERS = ["anthropic", "openai", "gemini", "deepseek", "grok"];

async function showSettings() {
  try {
    const cfg = await api("/api/settings");
    $("s-provider").value = cfg.provider || "anthropic";
    KEYED_PROVIDERS.forEach((p) => {
      $(`s-${p}`).value = "";
      setKeyState(`s-${p}-state`, cfg[`${p}_key`]);
    });
    $("s-sonar").value = "";
    setKeyState("s-sonar-state", cfg.sonar_token);
    $("s-snyk").value = "";
    setKeyState("s-snyk-state", cfg.snyk_token);
    openModal("settings-modal");
  } catch (e) {
    toast("Could not load settings: " + e.message, "error");
  }
}
function setKeyState(id, state) {
  const set = state === "set";
  const el = $(id);
  el.className = "key-state " + (set ? "set" : "");
  el.textContent = set ? "✓ A key is stored" : "No key stored yet";
}
$("nav-settings").onclick = showSettings;
$("save-settings").onclick = async () => {
  try {
    const body = { provider: $("s-provider").value };
    KEYED_PROVIDERS.forEach((p) => { body[`${p}_key`] = $(`s-${p}`).value; });
    body.sonar_token = $("s-sonar").value;
    body.snyk_token = $("s-snyk").value;
    await api("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    closeModal("settings-modal");
    toast("Settings saved", "ok");
  } catch (e) {
    toast("Save failed: " + e.message, "error");
  }
};

/* ============================================================
   Validate with AI
   ============================================================ */
$("validate-btn").onclick = async () => {
  if (!currentScan) return;
  const btn = $("validate-btn");
  const p = $("validate-progress");
  btn.disabled = true;
  p.className = "inline-note";
  p.innerHTML = `<span class="spinner" style="display:inline-block;color:var(--primary)"></span> Validating…`;
  try {
    const res = await api(`/api/scans/${currentScan.id}/validate`, { method: "POST" });
    p.className = "inline-note ok";
    p.textContent = `Validated ${res.validated ?? ""} findings`;
    toast("AI validation complete", "ok");
    const s = await api(`/api/scans/${currentScan.id}`);
    renderResults(s);
  } catch (e) {
    p.className = "inline-note error";
    p.textContent = "Error: " + e.message;
    toast("Validation failed", "error");
  } finally {
    btn.disabled = false;
  }
};

/* ============================================================
   Boot
   ============================================================ */
$("browse-btn").onclick = async () => {
  const btn = $("browse-btn");
  btn.disabled = true;
  try {
    // Opens the native folder dialog on this machine (local single-user app).
    const res = await api("/api/pick-folder", { method: "POST" });
    if (res.path) {
      $("project-path").value = res.path;
      $("project-path").focus();
    }
  } catch (e) {
    toast(e.message || "Folder picker unavailable — type the path manually", "error");
  } finally {
    btn.disabled = false;
  }
};
$("analyze-btn").onclick = analyzeCodebase;
$("run-scan").onclick = runScan;
$("project-path").addEventListener("keydown", (e) => { if (e.key === "Enter") analyzeCodebase(); });

// Start clean on the New Scan (Analyze) card — results appear only after a scan
// is run or opened from history, preserving the Analyze → review → run flow.
initTheme();
loadHistory();
