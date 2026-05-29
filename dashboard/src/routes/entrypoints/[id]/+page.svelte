<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { getEntrypoint, backendKey, type Backend, type Entrypoint } from '$lib/api';
  import { isAuthenticated } from '$lib/auth';

  let entrypoint = $state<Entrypoint | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let lastRefresh = $state<Date | null>(null);
  let poll: ReturnType<typeof setInterval> | null = null;

  const id = $derived($page.params.id ?? '');

  function isBackendDown(ep: Entrypoint, backend: Backend): boolean {
    const key = backendKey(backend);
    return (ep.unhealthy_backends ?? []).some((u) => u.address === key);
  }

  function backendDownReason(
    ep: Entrypoint,
    backend: Backend
  ): { kind: string; message: string } | null {
    const key = backendKey(backend);
    const u = (ep.unhealthy_backends ?? []).find((x) => x.address === key);
    return u ? { kind: u.kind, message: u.message } : null;
  }

  async function load(silent = false) {
    if (!id) {
      return;
    }
    if (!silent) {
      loading = true;
    }
    try {
      entrypoint = await getEntrypoint(id);
      error = null;
      lastRefresh = new Date();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    if (!isAuthenticated()) {
      goto('./login');
      return;
    }
    void load();
    poll = setInterval(() => void load(true), 5000);
  });

  onDestroy(() => {
    if (poll) {
      clearInterval(poll);
    }
  });

  function timeAgo(d: Date | null): string {
    if (!d) {
      return '';
    }
    const s = Math.floor((Date.now() - d.getTime()) / 1000);
    if (s < 5) {
      return 'just now';
    }
    if (s < 60) {
      return `${s}s ago`;
    }
    return `${Math.floor(s / 60)}m ago`;
  }
</script>

<header class="page-header">
  <div>
    <a href="/" class="back">← Entrypoints</a>
    <h1>{entrypoint?.name ?? id}</h1>
    <p class="subtitle mono">{id}</p>
  </div>
  <div class="header-actions">
    {#if lastRefresh}
      <span class="refresh-meta">updated {timeAgo(lastRefresh)}</span>
    {/if}
    <button class="btn-secondary" onclick={() => load()} disabled={loading}>
      {loading ? 'loading…' : 'Refresh'}
    </button>
  </div>
</header>

{#if error}
  <div class="alert">
    <strong>error</strong> {error}
  </div>
{/if}

{#if entrypoint}
  <section class="grid">
    <div class="card">
      <h2>Overview</h2>
      <dl>
        <dt>Protocol</dt>
        <dd><span class="badge badge-{entrypoint.protocol.toLowerCase()}">{entrypoint.protocol.toUpperCase()}</span></dd>
        <dt>Priority</dt>
        <dd class="mono">{entrypoint.config.priority}</dd>
        <dt>Source</dt>
        <dd class="mono">{entrypoint.source ?? 'api'}</dd>
      </dl>
    </div>

    <div class="card">
      <h2>Features</h2>
      <div class="feature-grid">
        <div class="feature" class:on={entrypoint.config.tls}>
          <span>TLS</span>
          <span class="state">{entrypoint.config.tls ? 'on' : 'off'}</span>
        </div>
        <div class="feature" class:on={entrypoint.config.https_redirect}>
          <span>HTTPS redirect</span>
          <span class="state">{entrypoint.config.https_redirect ? 'on' : 'off'}</span>
        </div>
        <div class="feature" class:on={entrypoint.config.sticky_session}>
          <span>Sticky session</span>
          <span class="state">{entrypoint.config.sticky_session ? 'on' : 'off'}</span>
        </div>
        <div class="feature" class:on={entrypoint.config.compress}>
          <span>Gzip</span>
          <span class="state">{entrypoint.config.compress ? 'on' : 'off'}</span>
        </div>
        <div class="feature" class:on={entrypoint.config.strip_prefix}>
          <span>Strip prefix</span>
          <span class="state">{entrypoint.config.strip_prefix ? 'on' : 'off'}</span>
        </div>
        <div class="feature" class:on={entrypoint.config.backend_timeout != null}>
          <span>Backend timeout</span>
          <span class="state mono">
            {entrypoint.config.backend_timeout == null
              ? 'default'
              : entrypoint.config.backend_timeout === 0
                ? '∞'
                : `${entrypoint.config.backend_timeout}s`}
          </span>
        </div>
      </div>
    </div>
  </section>

  <section class="card">
    <h2>Hostnames</h2>
    {#if entrypoint.config.hostnames.length === 0}
      <p class="muted">no hostnames configured</p>
    {:else}
      <div class="chips">
        {#each entrypoint.config.hostnames as host}
          <span class="chip mono">{host}</span>
        {/each}
      </div>
    {/if}
  </section>

  {#if (entrypoint.config.ip_allow_list ?? []).length > 0}
    <section class="card">
      <h2>
        IP allow-list
        <span class="header-badge">{entrypoint.config.ip_allow_list?.length}</span>
      </h2>
      <p class="muted">
        Requests from clients outside these ranges are rejected with
        <span class="mono">403 Forbidden</span> before reaching the backend.
      </p>
      <div class="chips">
        {#each entrypoint.config.ip_allow_list ?? [] as cidr}
          <span class="chip mono">{cidr}</span>
        {/each}
      </div>
    </section>
  {/if}

  <section class="card">
    <h2>Backends</h2>
    {#if entrypoint.backends.length === 0}
      <p class="muted">no backends</p>
    {:else}
      <table class="backends-table">
        <thead>
          <tr>
            <th>Address</th>
            <th>Weight</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {#each entrypoint.backends as backend}
            {@const reason = backendDownReason(entrypoint, backend)}
            <tr>
              <td class="mono">{backendKey(backend)}</td>
              <td class="mono">{backend.weight}</td>
              <td>
                {#if reason}
                  <div class="status-stack">
                    <span class="status-pill down">
                      down · {reason.kind.replaceAll('_', ' ')}
                    </span>
                    <span class="status-reason mono">{reason.message}</span>
                  </div>
                {:else}
                  <span class="status-pill up">healthy</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>

  {#if (entrypoint.diagnostics ?? []).length > 0}
    <section class="card">
      <h2>
        Diagnostics
        <span class="diag-count">{(entrypoint.diagnostics ?? []).length}</span>
      </h2>
      <ul class="diag-list">
        {#each entrypoint.diagnostics ?? [] as diag}
          <li class="diag diag-{diag.severity}">
            <div class="diag-head">
              <span class="diag-glyph">
                {#if diag.severity === 'error'}✗{:else if diag.severity === 'warn'}⚠{:else}ℹ{/if}
              </span>
              <span class="diag-code mono">{diag.code}</span>
              <span class="diag-message">{diag.message}</span>
            </div>
            {#if diag.label || diag.value}
              <div class="diag-meta mono">
                {#if diag.label}<span>{diag.label}</span>{/if}
                {#if diag.value}<span class="diag-value">= {diag.value}</span>{/if}
              </div>
            {/if}
            {#if diag.hint}
              <div class="diag-hint">→ {diag.hint}</div>
            {/if}
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  {#if entrypoint.config.headers && Object.keys(entrypoint.config.headers).length > 0}
    <section class="card">
      <h2>Custom headers</h2>
      <table class="kv-table">
        <tbody>
          {#each Object.entries(entrypoint.config.headers) as [k, v]}
            <tr>
              <td class="mono k">{k}</td>
              <td class="mono">{v}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  <section class="card">
    <h2>Raw config</h2>
    <pre class="mono">{JSON.stringify(entrypoint, null, 2)}</pre>
  </section>
{:else if !loading && !error}
  <div class="empty-state">
    entrypoint not found
  </div>
{/if}

<style>
  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    margin-bottom: 1.75rem;
    gap: 1rem;
  }
  .back {
    display: inline-block;
    color: var(--fg-2);
    font-size: 0.78rem;
    margin-bottom: 0.5rem;
  }
  .back:hover {
    color: var(--fg-0);
  }
  h1 {
    margin: 0;
    font-size: 1.5rem;
    font-weight: 600;
    letter-spacing: -0.02em;
  }
  .subtitle {
    margin: 0.25rem 0 0;
    color: var(--fg-3);
    font-size: 0.75rem;
  }
  .header-actions {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  .refresh-meta {
    color: var(--fg-3);
    font-size: 0.75rem;
  }
  .btn-secondary {
    background: var(--bg-2);
    color: var(--fg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.5rem 0.875rem;
    font-size: 0.8rem;
    font-weight: 500;
  }
  .btn-secondary:hover {
    background: var(--bg-hover);
    color: var(--fg-0);
  }
  .btn-secondary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .alert {
    background: var(--danger-bg);
    border: 1px solid var(--danger);
    color: var(--fg-0);
    padding: 0.75rem 1rem;
    border-radius: var(--radius);
    margin-bottom: 1rem;
    font-size: 0.825rem;
  }
  .alert strong {
    color: var(--danger);
    margin-right: 0.5rem;
    text-transform: uppercase;
    font-size: 0.7rem;
    letter-spacing: 0.08em;
  }

  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  .card {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.1rem 1.25rem;
    margin-bottom: 1rem;
  }
  .card h2 {
    margin: 0 0 0.9rem;
    font-size: 0.72rem;
    font-weight: 600;
    color: var(--fg-2);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  dl {
    margin: 0;
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.5rem 1rem;
    align-items: center;
  }
  dt {
    color: var(--fg-2);
    font-size: 0.78rem;
  }
  dd {
    margin: 0;
    font-size: 0.825rem;
    color: var(--fg-0);
  }

  .feature-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px;
  }
  .feature {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.4rem 0.625rem;
    background: var(--bg-2);
    border-radius: var(--radius-sm);
    font-size: 0.78rem;
    color: var(--fg-2);
  }
  .feature.on {
    background: var(--success-bg);
    color: var(--fg-0);
  }
  .feature .state {
    font-size: 0.72rem;
    color: var(--fg-3);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .feature.on .state {
    color: var(--success);
  }

  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
  }
  .chip {
    background: var(--bg-3);
    color: var(--fg-1);
    padding: 3px 9px;
    border-radius: 4px;
    font-size: 0.76rem;
  }

  .backends-table,
  .kv-table {
    width: 100%;
    border-collapse: collapse;
  }
  .backends-table th {
    text-align: left;
    padding: 0.4rem 0.5rem;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--fg-2);
    font-weight: 500;
    border-bottom: 1px solid var(--border);
  }
  .backends-table td,
  .kv-table td {
    padding: 0.55rem 0.5rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.8rem;
  }
  .status-pill {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    font-family: var(--font-mono);
    text-transform: uppercase;
  }
  .status-pill.up {
    background: var(--success-bg);
    color: var(--success);
  }
  .status-pill.down {
    background: var(--danger-bg);
    color: var(--danger);
  }
  .status-stack {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
  }
  .status-reason {
    font-size: 0.75rem;
    color: var(--muted);
    line-height: 1.3;
    word-break: break-word;
  }
  .backends-table tbody tr:last-child td,
  .kv-table tbody tr:last-child td {
    border-bottom: none;
  }
  .kv-table td.k {
    color: var(--fg-2);
    width: 30%;
  }

  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    font-family: var(--font-mono);
  }
  .badge-http {
    background: var(--accent-bg);
    color: var(--accent);
  }
  .badge-tcp {
    background: rgba(240, 180, 41, 0.12);
    color: var(--warning);
  }
  .badge-udp {
    background: rgba(187, 115, 255, 0.12);
    color: #bb73ff;
  }

  .muted {
    color: var(--fg-3);
    font-size: 0.82rem;
    margin: 0;
  }

  pre {
    margin: 0;
    padding: 0.75rem 0.9rem;
    background: var(--bg-0);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    font-size: 0.76rem;
    color: var(--fg-1);
    overflow-x: auto;
    line-height: 1.55;
    max-height: 400px;
  }

  .empty-state {
    text-align: center;
    color: var(--fg-3);
    padding: 3rem;
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
  }

  @media (max-width: 900px) {
    .grid,
    .feature-grid {
      grid-template-columns: 1fr;
    }
  }

  .diag-count {
    display: inline-block;
    background: var(--bg-3);
    color: var(--fg-2);
    font-size: 0.7rem;
    font-weight: 500;
    padding: 1px 7px;
    border-radius: 999px;
    margin-left: 0.5rem;
    vertical-align: middle;
  }
  .diag-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .diag {
    border: 1px solid var(--border);
    border-left-width: 3px;
    border-radius: var(--radius);
    padding: 0.625rem 0.875rem;
    background: var(--bg-2);
  }
  .diag-error {
    border-left-color: var(--danger);
  }
  .diag-warn {
    border-left-color: var(--warning);
  }
  .diag-info {
    border-left-color: var(--accent);
  }
  .diag-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.825rem;
  }
  .diag-glyph {
    font-size: 0.95rem;
    line-height: 1;
  }
  .diag-error .diag-glyph {
    color: var(--danger);
  }
  .diag-warn .diag-glyph {
    color: var(--warning);
  }
  .diag-info .diag-glyph {
    color: var(--accent);
  }
  .diag-code {
    background: var(--bg-3);
    color: var(--fg-1);
    padding: 1px 7px;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 600;
  }
  .diag-message {
    color: var(--fg-0);
    flex: 1;
  }
  .diag-meta {
    color: var(--fg-3);
    font-size: 0.72rem;
    margin-top: 0.35rem;
    margin-left: 1.45rem;
    display: flex;
    gap: 0.4rem;
  }
  .diag-value {
    color: var(--fg-2);
  }
  .diag-hint {
    color: var(--fg-2);
    font-size: 0.78rem;
    margin-top: 0.35rem;
    margin-left: 1.45rem;
  }
</style>
