// Copyright (c) 2026 Parrish Lyon. PL-SENTINELGO-20260914
'use strict';
const byId = id => document.getElementById(id);
let lastResult = null;
fetch('/health').then(r => r.json()).then(d => { byId('version').textContent = 'GO ENGINE / ' + d.identity.version; }).catch(() => { byId('version').textContent = 'SERVER UNAVAILABLE'; });
byId('upload').addEventListener('submit', async event => {
  event.preventDefault(); const file = byId('file').files[0]; if (!file) return;
  if (file.size > 64 * 1024 * 1024) { byId('status').textContent = 'CSV exceeds 64 MiB.'; return; }
  byId('analyze').disabled = true; byId('status').textContent = 'Processing with the Go engine...';
  byId('results').hidden = true; lastResult = null;
  try {
    const form = new FormData(); form.append('file', file);
    const headers = {}; const token = byId('token').value; if (token) headers.Authorization = 'Bearer ' + token;
    const response = await fetch('/upload', { method: 'POST', body: form, headers, credentials: 'omit' });
    const data = await response.json(); if (!response.ok) throw new Error(data.error || 'Analysis failed');
    lastResult = data; byId('rows').textContent = data.total_rows.toLocaleString();
    byId('flagged').textContent = data.total_flagged_rows.toLocaleString();
    byId('volume').textContent = data.statistics.total_volume.toLocaleString(undefined, { maximumFractionDigits: 2 });
    byId('clusters').textContent = data.clusters.length.toLocaleString(); byId('digest').textContent = data.dataset_sha256;
    byId('warnings').textContent = data.warnings.join(' ');
    const distribution = byId('distribution'); distribution.replaceChildren();
    for (const grade of ['CRITICAL RISK', 'INVESTIGATE', 'HIGH RISK', 'LOW RISK']) {
      const row = document.createElement('p'); row.textContent = grade + ': ' + data.risk_counts[grade].toLocaleString(); distribution.append(row);
    }
    const shown = data.flagged_rows.slice(0, 200); const body = byId('transactions'); body.replaceChildren();
    for (const row of shown) {
      const tr = document.createElement('tr');
      for (const value of [row.order_id, row.timestamp, row.user_id, row.order_value, row.risk_score, row.risk_grade, row.flag_reason]) {
        const td = document.createElement('td'); td.textContent = String(value ?? ''); tr.append(td);
      } body.append(tr);
    }
    byId('limit').textContent = `Showing ${shown.length} of ${data.total_flagged_rows} flagged records. JSON contains ${data.flagged_rows.length}.` + (data.flagged_rows_truncated ? ' Server result cap applied; aggregate counts are complete.' : '');
    byId('results').hidden = false; byId('status').textContent = 'Analysis complete. Data remains in this tab until you navigate away or replace it.';
  } catch (error) { byId('status').textContent = error.message; }
  finally { byId('analyze').disabled = false; }
});
byId('export').addEventListener('click', () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'sentinelgo-analysis.json';
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
