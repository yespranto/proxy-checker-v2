(() => {
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.content : '';

  const state = {
    page: 1,
    perPage: 50,
    sort: 'id',
    dir: 'DESC',
    selectedIds: new Set(),
    activeJobId: null,
    pollTimer: null,
  };

  function esc(val) {
    if (val === null || val === undefined) return '';
    return String(val)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  async function api(url, options = {}) {
    const headers = Object.assign({}, options.headers || {});
    if (options.method && options.method !== 'GET') {
      headers['X-CSRF-Token'] = csrfToken;
    }
    const res = await fetch(url, Object.assign({}, options, { headers }));
    const data = await res.json().catch(() => ({ ok: false, error: 'Invalid server response' }));
    if (res.status === 401) {
      window.location.reload();
      throw new Error('Session expired');
    }
    if (!res.ok || data.ok === false) {
      throw new Error(data.error || `Request failed (${res.status})`);
    }
    return data;
  }

  function showAlert(id, msg, type = 'info') {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = msg;
    el.className = 'alert ' + (type === 'error' ? 'alert-error' : type === 'ok' ? 'alert-ok' : '');
    el.classList.remove('hidden');
  }

  function hideAlert(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('hidden');
  }

  function currentFiltersQuery() {
    const q = new URLSearchParams();
    const status = document.getElementById('filter-status').value;
    const type = document.getElementById('filter-type').value;
    const country = document.getElementById('filter-country').value.trim();
    const lat = document.getElementById('filter-latency').value.trim();
    const search = document.getElementById('filter-q').value.trim();
    if (status) q.set('status', status);
    if (type) q.set('type', type);
    if (country) q.set('country', country);
    if (lat) q.set('max_latency', lat);
    if (search) q.set('q', search);
    return q;
  }

  async function loadStats() {
    try {
      const data = await api('/api/stats.php');
      const t = data.totals;
      document.getElementById('stat-total').textContent = t.total.toLocaleString();
      document.getElementById('stat-breakdown-status').textContent =
        `${t.alive} alive · ${t.dead} dead · ${t.unchecked} unchecked`;
      document.getElementById('stat-alive-pct').textContent = `${t.alive_pct}%`;
      document.getElementById('stat-alive-count').textContent = `${t.alive} alive of ${t.alive + t.dead} checked`;
      document.getElementById('stat-avg-latency').textContent =
        t.avg_latency_ms !== null ? `${t.avg_latency_ms} ms` : '—';
      document.getElementById('stat-by-type').textContent =
        data.by_type.length > 0
          ? data.by_type.map(x => `${x.type.toUpperCase()}: ${x.alive}/${x.total}`).join(' · ')
          : 'No proxies yet';

      const q = data.quota;
      const pct = q.limit > 0 ? Math.min(100, Math.round((q.used / q.limit) * 100)) : 0;
      document.getElementById('stat-quota-rem').textContent = q.remaining.toLocaleString();
      document.getElementById('stat-quota-bar').style.width = `${pct}%`;
      document.getElementById('stat-quota-sub').textContent = `${q.used} / ${q.limit} used (${q.day})`;
    } catch (err) {
      console.error(err);
    }
  }

  async function loadProxies() {
    const q = currentFiltersQuery();
    q.set('page', String(state.page));
    q.set('per_page', String(state.perPage));
    q.set('sort', state.sort);
    q.set('dir', state.dir);

    const tbody = document.getElementById('proxies-tbody');
    try {
      const data = await api(`/api/proxies.php?${q.toString()}`);
      document.getElementById('page-info').textContent =
        `Page ${data.page} of ${data.pages} (${data.total.toLocaleString()} total)`;
      document.getElementById('btn-prev-page').disabled = data.page <= 1;
      document.getElementById('btn-next-page').disabled = data.page >= data.pages;

      if (!data.items.length) {
        tbody.innerHTML = '<tr><td colspan="10" class="empty-cell">No proxies match the current filters.</td></tr>';
        document.getElementById('select-all').checked = false;
        return;
      }

      tbody.innerHTML = data.items.map(p => {
        const checked = state.selectedIds.has(p.id) ? 'checked' : '';
        const statusBadge = p.status === 'alive'
          ? '<span class="badge badge-ok">alive</span>'
          : p.status === 'dead'
            ? '<span class="badge badge-bad">dead</span>'
            : '<span class="badge badge-muted">unchecked</span>';

        const anonBadge = p.anonymity
          ? `<span class="badge ${p.anonymity === 'elite' ? 'badge-ok' : p.anonymity === 'anonymous' ? 'badge-warn' : 'badge-bad'}">${esc(p.anonymity)}</span>`
          : '<span class="muted">—</span>';

        const riskVal = p.risk_score !== null
          ? `<span class="${p.risk_score >= 60 ? 'text-bad' : p.risk_score >= 30 ? 'text-warn' : 'text-ok'}">${p.risk_score}</span>`
          : '<span class="muted">—</span>';

        const loc = [p.country_code, p.city].filter(Boolean).join(' · ');
        const isp = p.isp || p.org || '';
        const authTag = p.has_auth ? ' <span class="badge badge-muted" title="Credentials stored encrypted">auth</span>' : '';
        const labelTag = p.label ? ` <span class="muted">(${esc(p.label)})</span>` : '';

        return `<tr>
          <td class="col-check"><input type="checkbox" class="row-check" data-id="${p.id}" ${checked}></td>
          <td class="mono">${esc(p.host)}:${p.port}${authTag}${labelTag}</td>
          <td><code>${esc(p.type)}</code></td>
          <td>${statusBadge}</td>
          <td>${p.latency_ms !== null ? `${p.latency_ms} ms` : '<span class="muted">—</span>'}</td>
          <td class="mono">${p.exit_ip ? esc(p.exit_ip) : '<span class="muted">—</span>'}</td>
          <td>${loc ? esc(loc) : '<span class="muted">—</span>'}${isp ? `<div class="muted" style="font-size:11.5px">${esc(isp)}</div>` : ''}</td>
          <td>${anonBadge}</td>
          <td>${riskVal}</td>
          <td class="muted">${p.last_checked_at ? esc(p.last_checked_at.replace('T', ' ').replace('Z', '')) : '—'}</td>
        </tr>`;
      }).join('');

      document.querySelectorAll('.row-check').forEach(cb => {
        cb.addEventListener('change', (e) => {
          const id = Number(e.target.dataset.id);
          if (e.target.checked) state.selectedIds.add(id);
          else state.selectedIds.delete(id);
        });
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="10" class="empty-cell text-bad">${esc(err.message)}</td></tr>`;
    }
  }

  function renderJob(job) {
    const panel = document.getElementById('job-panel');
    if (!job) {
      panel.classList.add('hidden');
      return;
    }
    panel.classList.remove('hidden');
    document.getElementById('job-id-label').textContent = `#${job.id}`;
    document.getElementById('job-meta').textContent =
      `Timeout ${job.timeout_s}s · Retries ${job.retries}`;

    const badge = document.getElementById('job-status-badge');
    badge.textContent = job.status;
    badge.className = 'badge ' + (
      job.status === 'done' ? 'badge-ok'
      : job.status === 'cancelled' || job.status === 'failed' ? 'badge-bad'
      : 'badge-warn'
    );

    const pct = job.total > 0 ? Math.min(100, Math.round((job.done / job.total) * 100)) : 0;
    document.getElementById('job-progress-bar').style.width = `${pct}%`;
    document.getElementById('job-done').textContent = String(job.done);
    document.getElementById('job-total').textContent = String(job.total);
    document.getElementById('job-alive').textContent = String(job.alive);
    document.getElementById('job-dead').textContent = String(job.dead);

    const isActive = job.status === 'queued' || job.status === 'running';
    document.getElementById('btn-cancel-job').disabled = !isActive;
  }

  function startJobPolling(jobId) {
    state.activeJobId = jobId;
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }

    const poll = async () => {
      try {
        const data = await api(`/api/jobs.php?id=${jobId}`);
        renderJob(data.job);
        await Promise.all([loadStats(), loadProxies()]);
        if (data.job.status !== 'queued' && data.job.status !== 'running') {
          clearInterval(state.pollTimer);
          state.pollTimer = null;
        }
      } catch (err) {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
      }
    };

    poll();
    state.pollTimer = setInterval(poll, 1500);
  }

  async function resumeLatestActiveJob() {
    try {
      const data = await api('/api/jobs.php');
      if (data.jobs && data.jobs.length > 0) {
        const latest = data.jobs[0];
        renderJob(latest);
        if (latest.status === 'queued' || latest.status === 'running') {
          startJobPolling(latest.id);
        }
      }
    } catch (err) {
      console.error(err);
    }
  }

  async function startJob(payload) {
    hideAlert('table-feedback');
    const timeout = Number(document.getElementById('opt-timeout').value) || 12;
    const retries = Number(document.getElementById('opt-retries').value) || 1;
    try {
      const data = await api('/api/jobs.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({}, payload, { timeout, retries })),
      });
      renderJob(data.job);
      startJobPolling(data.job_id);
      await loadStats();
    } catch (err) {
      showAlert('table-feedback', err.message, 'error');
    }
  }

  // Event listeners
  document.getElementById('btn-logout').addEventListener('click', async () => {
    await api('/api/auth.php?action=logout', { method: 'POST' });
    window.location.reload();
  });

  document.getElementById('import-file').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    document.getElementById('import-text').value = await file.text();
  });

  document.getElementById('btn-import').addEventListener('click', async () => {
    hideAlert('import-feedback');
    const errWrap = document.getElementById('import-errors-wrap');
    errWrap.classList.add('hidden');
    const text = document.getElementById('import-text').value;
    const label = document.getElementById('import-label').value.trim();

    try {
      const data = await api('/api/proxies.php?action=import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, label }),
      });
      showAlert(
        'import-feedback',
        `Imported ${data.inserted} new, updated ${data.updated} existing (${data.errors.length} invalid lines).`,
        'ok'
      );
      if (data.errors.length > 0) {
        document.getElementById('import-errors-summary').textContent =
          `${data.errors.length} invalid line(s)`;
        document.getElementById('import-errors-list').innerHTML = data.errors
          .slice(0, 100)
          .map(e => `<li>Line ${e.line} (<code>${esc(e.preview)}</code>): ${esc(e.error)}</li>`)
          .join('');
        errWrap.classList.remove('hidden');
      }
      state.page = 1;
      await Promise.all([loadStats(), loadProxies()]);
    } catch (err) {
      showAlert('import-feedback', err.message, 'error');
    }
  });

  document.getElementById('btn-quick-check').addEventListener('click', async () => {
    hideAlert('import-feedback');
    const proxies = document.getElementById('import-text').value;
    const timeout = Number(document.getElementById('opt-timeout').value) || 12;
    const retries = Number(document.getElementById('opt-retries').value) || 1;
    try {
      showAlert('import-feedback', 'Running quick sync check (up to 10 proxies)...', 'info');
      const data = await api('/api/check.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxies, timeout, retries }),
      });
      const aliveCount = data.results.filter(r => r.alive).length;
      const summary = data.results
        .map(r => `${r.type}://${r.host}:${r.port} => ${r.alive ? `ALIVE ${r.latency_ms}ms (${r.exit_ip || ''} ${r.country_code || ''})` : `DEAD (${r.error || 'failed'})`}`)
        .join(' | ');
      showAlert('import-feedback', `Checked ${data.results.length}: ${aliveCount} alive. ${summary}`, aliveCount > 0 ? 'ok' : 'error');
      await loadStats();
    } catch (err) {
      showAlert('import-feedback', err.message, 'error');
    }
  });

  document.getElementById('btn-check-selected').addEventListener('click', () => {
    const ids = Array.from(state.selectedIds);
    if (!ids.length) {
      showAlert('table-feedback', 'Select at least one proxy first.', 'error');
      return;
    }
    startJob({ ids });
  });

  document.getElementById('btn-check-unchecked').addEventListener('click', () => {
    startJob({ all: true, status: 'unchecked' });
  });

  document.getElementById('btn-check-all').addEventListener('click', () => {
    startJob({ all: true });
  });

  document.getElementById('btn-cancel-job').addEventListener('click', async () => {
    if (!state.activeJobId) return;
    try {
      const data = await api(`/api/jobs.php?id=${state.activeJobId}&action=cancel`, { method: 'POST' });
      renderJob(data.job);
      if (state.pollTimer) {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
      }
      await loadStats();
    } catch (err) {
      showAlert('table-feedback', err.message, 'error');
    }
  });

  document.getElementById('btn-delete-selected').addEventListener('click', async () => {
    const ids = Array.from(state.selectedIds);
    if (!ids.length) {
      showAlert('table-feedback', 'Select at least one proxy to delete.', 'error');
      return;
    }
    try {
      const data = await api('/api/proxies.php', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids }),
      });
      ids.forEach(id => state.selectedIds.delete(id));
      showAlert('table-feedback', `Deleted ${data.deleted} proxies.`, 'ok');
      await Promise.all([loadStats(), loadProxies()]);
    } catch (err) {
      showAlert('table-feedback', err.message, 'error');
    }
  });

  document.getElementById('btn-delete-dead').addEventListener('click', async () => {
    try {
      const data = await api('/api/proxies.php', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'dead' }),
      });
      state.selectedIds.clear();
      showAlert('table-feedback', `Deleted ${data.deleted} dead proxies.`, 'ok');
      await Promise.all([loadStats(), loadProxies()]);
    } catch (err) {
      showAlert('table-feedback', err.message, 'error');
    }
  });

  function triggerExport(format) {
    const q = currentFiltersQuery();
    q.set('action', 'export');
    q.set('format', format);
    window.location.href = `/api/proxies.php?${q.toString()}`;
  }

  document.getElementById('btn-export-txt').addEventListener('click', () => triggerExport('txt'));
  document.getElementById('btn-export-csv').addEventListener('click', () => triggerExport('csv'));

  document.getElementById('select-all').addEventListener('change', (e) => {
    document.querySelectorAll('.row-check').forEach(cb => {
      cb.checked = e.target.checked;
      const id = Number(cb.dataset.id);
      if (e.target.checked) state.selectedIds.add(id);
      else state.selectedIds.delete(id);
    });
  });

  document.getElementById('btn-apply-filters').addEventListener('click', () => {
    state.page = 1;
    loadProxies();
  });

  document.getElementById('filter-q').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      state.page = 1;
      loadProxies();
    }
  });

  document.getElementById('per-page').addEventListener('change', (e) => {
    state.perPage = Number(e.target.value) || 50;
    state.page = 1;
    loadProxies();
  });

  document.getElementById('btn-prev-page').addEventListener('click', () => {
    if (state.page > 1) {
      state.page--;
      loadProxies();
    }
  });

  document.getElementById('btn-next-page').addEventListener('click', () => {
    state.page++;
    loadProxies();
  });

  document.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (state.sort === col) {
        state.dir = state.dir === 'ASC' ? 'DESC' : 'ASC';
      } else {
        state.sort = col;
        state.dir = col === 'latency_ms' || col === 'risk_score' ? 'ASC' : 'DESC';
      }
      loadProxies();
    });
  });

  // Initial load
  loadStats();
  loadProxies();
  resumeLatestActiveJob();
})();
