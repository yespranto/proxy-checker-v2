<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth.php';

start_app_session();
$user = current_user();
$csrf = csrf_token();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf-token" content="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
  <title>Proxy Checker Dashboard</title>
  <link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<?php if ($user === null): ?>
  <main class="auth-shell">
    <section class="auth-card">
      <div class="brand">
        <span class="brand-dot"></span>
        <h1>Proxy Checker</h1>
      </div>
      <p class="muted">Sign in to manage proxies, run background check jobs, and inspect exit telemetry.</p>
      <form id="login-form" class="stack" autocomplete="on">
        <input type="hidden" name="_csrf" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
        <label class="field">
          <span>Username</span>
          <input type="text" name="username" required autocomplete="username" autofocus>
        </label>
        <label class="field">
          <span>Password</span>
          <input type="password" name="password" required autocomplete="current-password">
        </label>
        <div id="login-error" class="alert alert-error hidden" role="alert"></div>
        <button type="submit" class="btn btn-primary">Sign In</button>
      </form>
    </section>
  </main>
  <script>
    (function () {
      const form = document.getElementById('login-form');
      const errBox = document.getElementById('login-error');
      const csrf = document.querySelector('meta[name="csrf-token"]').content;
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        errBox.classList.add('hidden');
        const fd = new FormData(form);
        try {
          const res = await fetch('/api/auth.php?action=login', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': csrf
            },
            body: JSON.stringify({
              username: fd.get('username'),
              password: fd.get('password'),
              _csrf: csrf
            })
          });
          const data = await res.json();
          if (!res.ok || !data.ok) {
            errBox.textContent = data.error || 'Login failed.';
            errBox.classList.remove('hidden');
            return;
          }
          window.location.reload();
        } catch (err) {
          errBox.textContent = 'Network error during login.';
          errBox.classList.remove('hidden');
        }
      });
    })();
  </script>
<?php else: ?>
  <header class="topbar">
    <div class="topbar-left">
      <span class="brand-dot"></span>
      <strong>Proxy Checker</strong>
      <span class="badge badge-muted">v2</span>
    </div>
    <div class="topbar-right">
      <span class="muted">Signed in as <strong><?= htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8') ?></strong></span>
      <button id="btn-logout" class="btn btn-ghost btn-sm" type="button">Log out</button>
    </div>
  </header>

  <main class="container">
    <!-- Stats cards -->
    <section class="stats-grid" aria-label="Statistics">
      <article class="stat-card">
        <div class="stat-label">Total Proxies</div>
        <div class="stat-value" id="stat-total">—</div>
        <div class="stat-sub" id="stat-breakdown-status">Loading...</div>
      </article>
      <article class="stat-card">
        <div class="stat-label">Alive Rate</div>
        <div class="stat-value text-ok" id="stat-alive-pct">—</div>
        <div class="stat-sub" id="stat-alive-count">0 alive</div>
      </article>
      <article class="stat-card">
        <div class="stat-label">Avg Latency</div>
        <div class="stat-value" id="stat-avg-latency">—</div>
        <div class="stat-sub" id="stat-by-type">No type data</div>
      </article>
      <article class="stat-card">
        <div class="stat-label">Daily Quota Remaining</div>
        <div class="stat-value" id="stat-quota-rem">—</div>
        <div class="progress-track"><div class="progress-fill" id="stat-quota-bar" style="width:0%"></div></div>
        <div class="stat-sub" id="stat-quota-sub">0 / 0 used today</div>
      </article>
    </section>

    <!-- Active Job Progress -->
    <section id="job-panel" class="panel hidden" aria-live="polite">
      <div class="panel-head">
        <div>
          <h2>Active Check Job <span id="job-id-label"></span></h2>
          <p class="muted" id="job-meta"></p>
        </div>
        <div class="row-actions">
          <span class="badge" id="job-status-badge">queued</span>
          <button id="btn-cancel-job" class="btn btn-danger btn-sm" type="button">Cancel Job</button>
        </div>
      </div>
      <div class="progress-track progress-lg">
        <div class="progress-fill" id="job-progress-bar" style="width:0%"></div>
      </div>
      <div class="job-counts">
        <span>Processed: <strong id="job-done">0</strong> / <strong id="job-total">0</strong></span>
        <span class="text-ok">Alive: <strong id="job-alive">0</strong></span>
        <span class="text-bad">Dead: <strong id="job-dead">0</strong></span>
      </div>
    </section>

    <!-- Import & Quick Check -->
    <section class="panel">
      <div class="panel-head">
        <h2>Import Proxies</h2>
        <span class="muted">Supports <code>host:port</code>, <code>host:port:user:pass</code>, <code>user:pass@host:port</code>, <code>scheme://...</code>, IPv6 <code>[::1]:8080</code> (max 5,000 lines)</span>
      </div>
      <div class="import-grid">
        <textarea id="import-text" rows="5" placeholder="socks5://user:pass@1.2.3.4:1080&#10;5.6.7.8:8080&#10;9.10.11.12:3128:user:p@ss http"></textarea>
        <div class="import-controls">
          <label class="field">
            <span>Upload .txt file</span>
            <input type="file" id="import-file" accept=".txt,.csv,text/plain">
          </label>
          <label class="field">
            <span>Optional Label</span>
            <input type="text" id="import-label" maxlength="64" placeholder="e.g. residential-us">
          </label>
          <div class="row-actions">
            <button id="btn-import" class="btn btn-primary" type="button">Import to List</button>
            <button id="btn-quick-check" class="btn btn-secondary" type="button" title="Run immediate sync check (max 10 lines)">Quick Check (&le;10)</button>
          </div>
        </div>
      </div>
      <div id="import-feedback" class="alert hidden"></div>
      <div id="import-errors-wrap" class="hidden">
        <details open>
          <summary id="import-errors-summary">Parse errors</summary>
          <ul id="import-errors-list" class="error-list"></ul>
        </details>
      </div>
    </section>

    <!-- Toolbar + Filters + Table -->
    <section class="panel">
      <div class="toolbar">
        <div class="row-actions">
          <button id="btn-check-selected" class="btn btn-primary btn-sm" type="button">Check Selected</button>
          <button id="btn-check-unchecked" class="btn btn-secondary btn-sm" type="button">Check Unchecked</button>
          <button id="btn-check-all" class="btn btn-secondary btn-sm" type="button">Check All</button>
          <button id="btn-delete-selected" class="btn btn-ghost btn-sm" type="button">Delete Selected</button>
          <button id="btn-delete-dead" class="btn btn-danger btn-sm" type="button">Delete Dead</button>
        </div>
        <div class="row-actions">
          <label class="inline-field">
            <span>Timeout</span>
            <input type="number" id="opt-timeout" min="3" max="30" value="12">s
          </label>
          <label class="inline-field">
            <span>Retries</span>
            <input type="number" id="opt-retries" min="0" max="2" value="1">
          </label>
          <button id="btn-export-txt" class="btn btn-ghost btn-sm" type="button">Export TXT</button>
          <button id="btn-export-csv" class="btn btn-ghost btn-sm" type="button">Export CSV</button>
        </div>
      </div>

      <div class="filters-bar">
        <input type="search" id="filter-q" placeholder="Search host, exit IP, ISP, label...">
        <select id="filter-status">
          <option value="">All Statuses</option>
          <option value="alive">Alive</option>
          <option value="dead">Dead</option>
          <option value="unchecked">Unchecked</option>
        </select>
        <select id="filter-type">
          <option value="">All Types</option>
          <option value="http">HTTP</option>
          <option value="https">HTTPS</option>
          <option value="socks4">SOCKS4</option>
          <option value="socks4a">SOCKS4A</option>
          <option value="socks5">SOCKS5</option>
          <option value="socks5h">SOCKS5H</option>
        </select>
        <input type="text" id="filter-country" maxlength="32" placeholder="Country (e.g. US)">
        <input type="number" id="filter-latency" min="0" placeholder="Max latency (ms)">
        <button id="btn-apply-filters" class="btn btn-secondary btn-sm" type="button">Filter</button>
      </div>

      <div id="table-feedback" class="alert hidden"></div>

      <div class="table-wrap">
        <table id="proxies-table">
          <thead>
            <tr>
              <th class="col-check"><input type="checkbox" id="select-all" aria-label="Select all on page"></th>
              <th data-sort="host" class="sortable">Proxy</th>
              <th data-sort="type" class="sortable">Type</th>
              <th data-sort="status" class="sortable">Status</th>
              <th data-sort="latency_ms" class="sortable">Latency</th>
              <th>Exit IP</th>
              <th data-sort="country_code" class="sortable">Location / ISP</th>
              <th data-sort="anonymity" class="sortable">Anonymity</th>
              <th data-sort="risk_score" class="sortable">Risk</th>
              <th data-sort="last_checked_at" class="sortable">Last Checked</th>
            </tr>
          </thead>
          <tbody id="proxies-tbody">
            <tr><td colspan="10" class="empty-cell">Loading proxies...</td></tr>
          </tbody>
        </table>
      </div>

      <div class="pagination-bar">
        <span class="muted" id="page-info">Page 1 of 1 (0 total)</span>
        <div class="row-actions">
          <select id="per-page">
            <option value="25">25 / page</option>
            <option value="50" selected>50 / page</option>
            <option value="100">100 / page</option>
            <option value="200">200 / page</option>
          </select>
          <button id="btn-prev-page" class="btn btn-ghost btn-sm" type="button">Prev</button>
          <button id="btn-next-page" class="btn btn-ghost btn-sm" type="button">Next</button>
        </div>
      </div>
    </section>
  </main>

  <script src="/assets/app.js"></script>
<?php endif; ?>
</body>
</html>
