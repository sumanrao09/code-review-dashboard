let currentScan = null;

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sevBadge(s) { return `<span class="badge sev-${s}">${s}</span>`; }

async function loadHistory() {
  const scans = await api('/api/scans');
  const rows = scans.map(s => {
    const c = s.severity_counts;
    return `<tr data-id="${s.id}"><td>${s.id}</td><td>${escapeHtml(s.project_path)}</td>
      <td>${s.started_at.slice(0,19)}</td>
      <td>${s.finished_at ? 'done' : 'running'}</td>
      <td>${sevBadge('critical')}${c.critical} ${sevBadge('high')}${c.high}
          ${sevBadge('medium')}${c.medium} ${sevBadge('low')}${c.low}</td></tr>`;
  }).join('');
  document.getElementById('history-table').innerHTML =
    `<tr><th>#</th><th>Project</th><th>Started</th><th>Status</th><th>Severity</th></tr>${rows}`;
  document.querySelectorAll('#history-table tr[data-id]').forEach(tr =>
    tr.onclick = () => openResults(Number(tr.dataset.id)));
}

async function runScan() {
  const path = document.getElementById('project-path').value.trim();
  const tools = [...document.querySelectorAll('#tool-checks input:checked')].map(c => c.value);
  const res = await api('/api/scans', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({project_path: path, tools}),
  });
  document.getElementById('warnings').innerHTML =
    res.warnings.map(w => `<div>⚠️ ${escapeHtml(w)}</div>`).join('');
  pollScan(res.scan_id);
}

async function pollScan(id) {
  const s = await api(`/api/scans/${id}`);
  if (!s.finished_at) { setTimeout(() => pollScan(id), 1500); }
  await loadHistory();
  openResults(id);
}

async function openResults(id) {
  currentScan = await api(`/api/scans/${id}`);
  document.getElementById('results').hidden = false;
  document.getElementById('result-id').textContent = id;
  const st = currentScan.tool_status;
  document.getElementById('tool-chips').innerHTML = Object.entries(st)
    .map(([t, v]) => `<span class="chip ${escapeHtml(v.status)}">${escapeHtml(t)}: ${escapeHtml(v.status)}${v.error ? ' — ' + escapeHtml(v.error) : ''}</span>`).join('');
  renderSummary();
  renderFindings('unified', '', '');
}

function renderSummary() {
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  currentScan.findings.forEach(f => counts[f.severity]++);
  const cards = Object.entries(counts).map(([s, n]) =>
    `<div class="card">${sevBadge(s)}<br><b>${n}</b></div>`).join('');
  const m = currentScan.metrics;
  const metricCard = m ? `<div class="card">Code lines<br><b>${m.total_code}</b></div>` : '';
  document.getElementById('summary-cards').innerHTML = cards + metricCard;
}

function renderFindings(tab, sevFilter, toolFilter) {
  const panel = document.getElementById('findings-panel');
  if (tab === 'scc') {
    const m = currentScan.metrics;
    panel.innerHTML = m ? `<p>Total code: ${m.total_code}, lines: ${m.total_lines},
      complexity: ${m.complexity}, COCOMO: ${m.cocomo_months} person-months</p>
      <table><tr><th>Language</th><th>Code</th><th>Complexity</th></tr>
      ${m.languages.map(l => `<tr><td>${escapeHtml(l.Name)}</td><td>${l.Code}</td><td>${l.Complexity||0}</td></tr>`).join('')}</table>`
      : '<p>No metrics.</p>';
    return;
  }
  // Dedup hint: findings across tools sharing file+line+cwe are "likely dup".
  const dupKeys = {};
  currentScan.findings.forEach(f => {
    const k = `${f.file}|${f.line}|${f.cwe || ''}`;
    dupKeys[k] = (dupKeys[k] || 0) + 1;
  });
  let items = currentScan.findings;
  if (tab !== 'unified') items = items.filter(f => f.tool === tab);
  if (sevFilter) items = items.filter(f => f.severity === sevFilter);
  if (toolFilter) items = items.filter(f => f.tool === toolFilter);
  panel.innerHTML = `<table><tr><th>Sev</th><th>Tool</th><th>File:Line</th>
    <th>Title</th><th>Verdict</th><th></th></tr>` + items.map(f => {
    const k = `${f.file}|${f.line}|${f.cwe || ''}`;
    const dup = f.cwe && dupKeys[k] > 1 ? '<span title="likely duplicate">⧉</span>' : '';
    return `<tr><td>${sevBadge(f.severity)}</td><td>${escapeHtml(f.tool)}</td>
      <td>${escapeHtml(f.file)}:${f.line ?? ''}</td><td>${escapeHtml(f.title)}</td>
      <td class="verdict-${escapeHtml(f.verdict||'')}">${escapeHtml(f.verdict) || ''}</td><td>${dup}</td></tr>`;
  }).join('') + '</table>';
}

document.getElementById('run-scan').onclick = runScan;
document.querySelectorAll('.tab').forEach(b => b.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  renderFindings(b.dataset.tab, document.getElementById('f-sev').value,
                 document.getElementById('f-tool').value);
});
['f-sev','f-tool'].forEach(id => document.getElementById(id).onchange = () => {
  const tab = document.querySelector('.tab.active').dataset.tab;
  renderFindings(tab, document.getElementById('f-sev').value,
                 document.getElementById('f-tool').value);
});
['critical','high','medium','low','info'].forEach(s => {
  document.getElementById('f-sev').innerHTML += `<option value="${s}">${s}</option>`;});
['semgrep','sonarqube','snyk'].forEach(t => {
  document.getElementById('f-tool').innerHTML += `<option value="${t}">${t}</option>`;});

async function showSettings() {
  const cfg = await api('/api/settings');
  document.getElementById('s-provider').value = cfg.provider || 'anthropic';
  document.getElementById('settings-status').textContent =
    `Anthropic key: ${cfg.anthropic_key}, OpenAI key: ${cfg.openai_key}`;
  document.getElementById('settings').hidden = false;
}
document.getElementById('nav-settings').onclick = showSettings;
document.getElementById('nav-home').onclick = () =>
  document.getElementById('settings').hidden = true;
document.getElementById('save-settings').onclick = async () => {
  await api('/api/settings', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      provider: document.getElementById('s-provider').value,
      anthropic_key: document.getElementById('s-anthropic').value,
      openai_key: document.getElementById('s-openai').value})});
  showSettings();
};

document.getElementById('validate-btn').onclick = async () => {
  if (!currentScan) return;
  const p = document.getElementById('validate-progress');
  p.textContent = 'validating…';
  try {
    const res = await api(`/api/scans/${currentScan.id}/validate`, {method: 'POST'});
    p.textContent = `validated ${res.validated} findings`;
    await openResults(currentScan.id);
  } catch (e) { p.textContent = 'error: ' + e.message; }
};

document.getElementById('report-btn').onclick = async () => {
  if (!currentScan) return;
  const client = prompt('Client / program name:', '') || '';
  const atype = prompt('Assessment type:', 'White-box source code review') || '';
  const includeFp = confirm('Include false positives in an appendix?');
  const res = await api(`/api/scans/${currentScan.id}/report`, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({meta: {client, assessment_type: atype,
      repos: currentScan.project_path}, include_false_positives: includeFp})});
  window.open(`/api/reports/${res.report_id}`, '_blank');
};

loadHistory();
