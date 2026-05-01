<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { goto } from '$app/navigation';
  import { listEntrypoints, type Entrypoint } from '$lib/api';
  import { isAuthenticated } from '$lib/auth';

  let entrypoints = $state<Entrypoint[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let lastRefresh = $state<Date | null>(null);
  let search = $state('');
  let protocolFilter = $state<'all' | 'Http' | 'Tcp' | 'Udp'>('all');

  let poll: ReturnType<typeof setInterval> | null = null;

  const filtered = $derived(
    entrypoints.filter((ep) => {
      if (protocolFilter !== 'all' && ep.protocol !== protocolFilter) return false;
      if (!search) return true;
      const q = search.toLowerCase();
      return (
        ep.name.toLowerCase().includes(q) ||
        ep.id.toLowerCase().includes(q) ||
        ep.config.hostnames.some((h) => h.toLowerCase().includes(q)) ||
        ep.backends.some((b) => b.toLowerCase().includes(q))
      );
    })
  );

  const stats = $derived({
    total: entrypoints.length,
    http: entrypoints.filter((e) => e.protocol === 'Http').length,
    tcp: entrypoints.filter((e) => e.protocol === 'Tcp').length,
    backends: entrypoints.reduce((n, e) => n + e.backends.length, 0),
    backendsDown: entrypoints.reduce((n, e) => n + (e.unhealthy_backends?.length ?? 0), 0),
    tls: entrypoints.filter((e) => e.config.tls).length
  });

  function isBackendDown(ep: Entrypoint, backend: string): boolean {
    return (ep.unhealthy_backends ?? []).includes(`${backend}:${ep.config.port}`);
  }

  function downCount(ep: Entrypoint): number {
    return ep.backends.filter((b) => isBackendDown(ep, b)).length;
  }

  async function load(silent = false) {
    if (!silent) loading = true;
    try {
      entrypoints = await listEntrypoints();
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
    if (poll) clearInterval(poll);
  });

  function timeAgo(d: Date | null): string {
    if (!d) return '';
    const s = Math.floor((Date.now() - d.getTime()) / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return `${s}s ago`;
    return `${Math.floor(s / 60)}m ago`;
  }
</script>

<header class="page-header">
  <div>
    <h1>Entrypoints</h1>
    <p class="subtitle">Routes served by the proxy</p>
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

<section class="stats">
  <div class="stat-card">
    <div class="stat-label">Entrypoints</div>
    <div class="stat-value">{stats.total}</div>
    <div class="stat-sub">{stats.http} HTTP · {stats.tcp} TCP</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Backends</div>
    <div class="stat-value">{stats.backends}</div>
    <div class="stat-sub">
      {#if stats.backendsDown > 0}
        <span class="stat-down">{stats.backendsDown} down</span> · {stats.backends - stats.backendsDown} healthy
      {:else}
        across all entrypoints
      {/if}
    </div>
  </div>
  <div class="stat-card">
    <div class="stat-label">TLS enabled</div>
    <div class="stat-value">{stats.tls}</div>
    <div class="stat-sub">{stats.total ? Math.round((stats.tls / stats.total) * 100) : 0}% of routes</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Status</div>
    <div class="stat-value healthy">
      <span class="dot"></span> live
    </div>
    <div class="stat-sub">polling every 5s</div>
  </div>
</section>

<section class="toolbar">
  <div class="search">
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="7" cy="7" r="5"/><path d="M11 11l3 3" stroke-linecap="round"/></svg>
    <input type="text" placeholder="search by name, hostname, backend…" bind:value={search} />
  </div>
  <div class="filters">
    {#each ['all', 'Http', 'Tcp', 'Udp'] as p}
      <button
        class="filter-chip"
        class:active={protocolFilter === p}
        onclick={() => (protocolFilter = p as typeof protocolFilter)}
      >
        {p}
      </button>
    {/each}
  </div>
</section>

{#if error}
  <div class="alert">
    <strong>error</strong> {error}
  </div>
{/if}

<section class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Protocol</th>
        <th>Hostnames</th>
        <th>Backends</th>
        <th>Features</th>
        <th>Source</th>
      </tr>
    </thead>
    <tbody>
      {#if loading && entrypoints.length === 0}
        <tr><td colspan="6" class="empty">loading…</td></tr>
      {:else if filtered.length === 0}
        <tr><td colspan="6" class="empty">no entrypoints match</td></tr>
      {:else}
        {#each filtered as ep (ep.id)}
          <tr class="clickable" onclick={() => goto(`/entrypoints/${encodeURIComponent(ep.id)}`)}>
            <td>
              <div class="cell-name">{ep.name}</div>
              <div class="cell-id mono">{ep.id}</div>
            </td>
            <td>
              <span class="badge badge-{ep.protocol.toLowerCase()}">{ep.protocol.toUpperCase()}</span>
            </td>
            <td>
              {#if ep.config.hostnames.length === 0}
                <span class="muted">—</span>
              {:else}
                <div class="hostnames">
                  {#each ep.config.hostnames.slice(0, 2) as h}
                    <span class="host mono">{h}</span>
                  {/each}
                  {#if ep.config.hostnames.length > 2}
                    <span class="more">+{ep.config.hostnames.length - 2}</span>
                  {/if}
                </div>
              {/if}
            </td>
            <td>
              <div class="backends-cell">
                <span class="backend-count mono">{ep.backends.length}</span>
                <div
                  class="health-bar"
                  title={downCount(ep) > 0
                    ? `${ep.backends.length - downCount(ep)}/${ep.backends.length} healthy`
                    : `${ep.backends.length} backends, all healthy`}
                >
                  {#each ep.backends as b, i}
                    <span
                      class="health-seg"
                      class:down={isBackendDown(ep, b)}
                      style="animation-delay: {i * 40}ms"
                    ></span>
                  {/each}
                </div>
              </div>
            </td>
            <td>
              <div class="features">
                {#if ep.config.tls}<span class="chip">TLS</span>{/if}
                {#if ep.config.https_redirect}<span class="chip">→HTTPS</span>{/if}
                {#if ep.config.sticky_session}<span class="chip">sticky</span>{/if}
                {#if ep.config.compress}<span class="chip">gzip</span>{/if}
                {#if ep.config.strip_prefix}<span class="chip">strip</span>{/if}
              </div>
            </td>
            <td>
              <span class="source mono">{ep.source ?? 'api'}</span>
            </td>
          </tr>
        {/each}
      {/if}
    </tbody>
  </table>
</section>

<style>
  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    margin-bottom: 1.75rem;
  }
  h1 {
    margin: 0;
    font-size: 1.5rem;
    font-weight: 600;
    letter-spacing: -0.02em;
  }
  .subtitle {
    margin: 0.25rem 0 0;
    color: var(--fg-2);
    font-size: 0.825rem;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  .refresh-meta {
    color: var(--fg-3);
    font-size: 0.75rem;
    margin-right: 0.25rem;
  }
  .btn-secondary {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.5rem 0.875rem;
    font-size: 0.8rem;
    font-weight: 500;
    transition: background 0.1s, border-color 0.1s;
    background: var(--bg-2);
    color: var(--fg-1);
  }
  .btn-secondary:hover {
    background: var(--bg-hover);
    color: var(--fg-0);
  }
  .btn-secondary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 1.5rem;
  }
  .stat-card {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1rem 1.125rem;
  }
  .stat-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--fg-2);
    font-weight: 500;
  }
  .stat-value {
    font-size: 1.75rem;
    font-weight: 600;
    margin-top: 0.25rem;
    letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
  }
  .stat-value.healthy {
    color: var(--success);
    font-size: 1.05rem;
    display: flex;
    align-items: center;
    gap: 0.4rem;
    margin-top: 0.6rem;
    margin-bottom: 0.1rem;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--success);
    box-shadow: 0 0 0 3px var(--success-bg);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
  .stat-sub {
    font-size: 0.75rem;
    color: var(--fg-3);
    margin-top: 0.25rem;
  }

  .toolbar {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 1rem;
    align-items: center;
  }
  .search {
    flex: 1;
    position: relative;
    display: flex;
    align-items: center;
  }
  .search :global(svg) {
    position: absolute;
    left: 0.75rem;
    width: 14px;
    height: 14px;
    color: var(--fg-3);
    pointer-events: none;
  }
  .search input {
    width: 100%;
    padding: 0.55rem 0.75rem 0.55rem 2.1rem;
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--fg-0);
    outline: none;
    transition: border-color 0.1s;
  }
  .search input:focus {
    border-color: var(--accent);
  }
  .search input::placeholder {
    color: var(--fg-3);
  }

  .filters {
    display: flex;
    gap: 4px;
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 3px;
  }
  .filter-chip {
    padding: 0.35rem 0.75rem;
    background: transparent;
    border: none;
    color: var(--fg-2);
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 500;
    text-transform: capitalize;
  }
  .filter-chip:hover {
    color: var(--fg-0);
  }
  .filter-chip.active {
    background: var(--bg-3);
    color: var(--fg-0);
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

  .table-wrap {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  thead {
    background: var(--bg-2);
  }
  th {
    text-align: left;
    padding: 0.65rem 1rem;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--fg-2);
    font-weight: 500;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 0.85rem 1rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.825rem;
    vertical-align: middle;
  }
  tbody tr:last-child td {
    border-bottom: none;
  }
  tbody tr {
    transition: background 0.08s;
  }
  tbody tr:hover {
    background: var(--bg-2);
  }
  tbody tr.clickable {
    cursor: pointer;
  }

  .empty {
    text-align: center;
    color: var(--fg-3);
    padding: 2rem !important;
  }

  .cell-name {
    font-weight: 500;
    color: var(--fg-0);
  }
  .cell-id {
    color: var(--fg-3);
    font-size: 0.7rem;
    margin-top: 2px;
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

  .hostnames {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
  }
  .host {
    background: var(--bg-3);
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 0.72rem;
    color: var(--fg-1);
  }
  .more {
    color: var(--fg-3);
    font-size: 0.72rem;
  }

  .backends-cell {
    display: flex;
    align-items: center;
    gap: 0.625rem;
  }
  .backend-count {
    font-weight: 600;
    color: var(--fg-0);
    min-width: 14px;
  }
  .health-bar {
    display: flex;
    gap: 2px;
    flex: 1;
    max-width: 80px;
  }
  .health-seg {
    flex: 1;
    height: 8px;
    background: var(--success);
    border-radius: 2px;
    opacity: 0;
    animation: fade-in 0.4s forwards;
  }
  .health-seg.down {
    background: var(--danger);
  }
  .stat-down {
    color: var(--danger);
    font-weight: 600;
  }
  @keyframes fade-in {
    to { opacity: 1; }
  }

  .features {
    display: flex;
    gap: 3px;
    flex-wrap: wrap;
  }
  .chip {
    background: var(--bg-3);
    color: var(--fg-1);
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 0.68rem;
    font-family: var(--font-mono);
    font-weight: 500;
  }

  .source {
    color: var(--fg-2);
    font-size: 0.72rem;
  }

  .muted {
    color: var(--fg-3);
  }

</style>
