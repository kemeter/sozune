<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { listProviders, type Provider } from '$lib/api';

  let providers = $state<Provider[]>([]);
  let loading = $state(true);
  let errorMsg = $state<string | null>(null);
  let lastFetch = $state<Date | null>(null);

  let poll: ReturnType<typeof setInterval> | null = null;

  async function refresh() {
    try {
      const res = await listProviders();
      providers = res.providers;
      errorMsg = null;
    } catch (e) {
      errorMsg = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
      lastFetch = new Date();
    }
  }

  onMount(() => {
    void refresh();
    // Counts come from live storage — refresh on the same cadence as Health.
    poll = setInterval(() => void refresh(), 5000);
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

  function statusOf(p: Provider): 'active' | 'disabled' | 'unconfigured' {
    if (p.enabled) return 'active';
    if (p.configured) return 'disabled';
    return 'unconfigured';
  }

  function statusLabel(s: 'active' | 'disabled' | 'unconfigured'): string {
    switch (s) {
      case 'active':
        return 'enabled';
      case 'disabled':
        return 'disabled';
      case 'unconfigured':
        return 'not configured';
    }
  }

  // Pre-compute the totals shown above the table.
  let activeCount = $derived(providers.filter((p) => p.enabled).length);
  let totalEntrypoints = $derived(
    providers.reduce((acc, p) => acc + p.entrypoint_count, 0)
  );
</script>

<header class="page-header">
  <div>
    <h1>Providers</h1>
    <p class="subtitle">Service discovery sources sōzune knows about</p>
  </div>
  <div class="header-actions">
    {#if lastFetch}
      <span class="refresh-meta">updated {timeAgo(lastFetch)}</span>
    {/if}
    <button class="btn-secondary" onclick={refresh} disabled={loading}>
      {loading ? 'loading…' : 'Refresh'}
    </button>
  </div>
</header>

<section class="stats">
  <div class="stat-card">
    <div class="stat-label">Enabled</div>
    <div class="stat-value">{activeCount}<span class="unit">/ {providers.length}</span></div>
    <div class="stat-sub">providers currently active</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Entrypoints</div>
    <div class="stat-value">{totalEntrypoints}</div>
    <div class="stat-sub">across every provider</div>
  </div>
</section>

{#if errorMsg}
  <div class="alert">
    <strong>error</strong> {errorMsg}
  </div>
{/if}

{#if !loading && providers.length > 0}
  <section class="card">
    <table>
      <thead>
        <tr>
          <th>Provider</th>
          <th>Status</th>
          <th class="num">Entrypoints</th>
        </tr>
      </thead>
      <tbody>
        {#each providers as p (p.name)}
          {@const s = statusOf(p)}
          {@const canDrill = p.entrypoint_count > 0}
          <tr class:disabled={s !== 'active'} class:clickable={canDrill}>
            <td>
              {#if canDrill}
                <a class="provider-link" href={`../entrypoints?source=${encodeURIComponent(p.name)}`}>
                  <span class="provider-name">{p.name}</span>
                </a>
              {:else}
                <span class="provider-name">{p.name}</span>
              {/if}
            </td>
            <td>
              <span class="status-pill" class:active={s === 'active'} class:warn={s === 'disabled'}>
                <span class="dot" class:active={s === 'active'} class:warn={s === 'disabled'}></span>
                {statusLabel(s)}
              </span>
            </td>
            <td class="num mono">{p.entrypoint_count}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>
{/if}

{#if !loading && providers.length === 0 && !errorMsg}
  <div class="empty">No providers reported.</div>
{/if}

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
    font-size: 1.5rem;
    font-weight: 600;
    margin-top: 0.35rem;
    letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
  }
  .unit {
    font-size: 0.85rem;
    color: var(--fg-2);
    font-weight: 500;
    margin-left: 4px;
  }
  .stat-sub {
    font-size: 0.75rem;
    color: var(--fg-3);
    margin-top: 0.25rem;
  }

  .card {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 0;
    overflow: hidden;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }
  th, td {
    text-align: left;
    padding: 0.7rem 1rem;
    font-size: 0.85rem;
    border-bottom: 1px solid var(--border);
  }
  tbody tr:last-child td {
    border-bottom: none;
  }
  th {
    font-weight: 500;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--fg-2);
    background: var(--bg-0);
  }
  td.num, th.num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  td.mono {
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
  tr.disabled .provider-name {
    color: var(--fg-2);
  }
  tr.disabled td.num {
    color: var(--fg-3);
  }
  .provider-name {
    font-weight: 500;
    color: var(--fg-0);
  }
  .provider-link {
    display: inline-block;
    text-decoration: none;
    color: inherit;
  }
  .provider-link:hover .provider-name {
    color: var(--accent);
  }
  tr.clickable {
    cursor: pointer;
  }
  tr.clickable:hover {
    background: var(--bg-2);
  }

  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.18rem 0.55rem;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 500;
    color: var(--fg-2);
    background: var(--bg-2);
    border: 1px solid var(--border);
  }
  .status-pill.active {
    color: var(--success);
    background: var(--success-bg);
    border-color: transparent;
  }
  .status-pill.warn {
    color: var(--fg-1);
    background: var(--bg-2);
  }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--fg-3);
  }
  .dot.active {
    background: var(--success);
  }
  .dot.warn {
    background: var(--fg-2);
  }

  .alert {
    background: var(--danger-bg);
    border: 1px solid var(--danger);
    color: var(--fg-0);
    padding: 0.85rem 1rem;
    border-radius: var(--radius);
    margin-bottom: 1.25rem;
    font-size: 0.825rem;
  }
  .alert strong {
    color: var(--danger);
    margin-right: 0.5rem;
    text-transform: uppercase;
    font-size: 0.7rem;
    letter-spacing: 0.08em;
  }

  .empty {
    color: var(--fg-2);
    font-size: 0.85rem;
    padding: 1.5rem;
    text-align: center;
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
  }
</style>
