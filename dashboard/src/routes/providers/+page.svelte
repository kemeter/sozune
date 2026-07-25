<script lang="ts">
  import ResourceTable from '$lib/ResourceTable.svelte';
  import { listProviders, type Provider } from '$lib/api';

  const columns = [
    { label: 'Provider' },
    { label: 'Status' },
    { label: 'Entrypoints', align: 'right' as const }
  ];

  // Counts come from live storage — refresh on the same cadence as Health.
  async function load(): Promise<Provider[]> {
    return (await listProviders()).providers;
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
</script>

<ResourceTable
  title="Providers"
  subtitle="Service discovery sources sōzune knows about"
  {columns}
  {load}
  key={(p: Provider) => p.name}
  emptyText="No providers reported."
>
  {#snippet beforeTable(providers: Provider[])}
    <section class="stats">
      <div class="stat-card">
        <div class="stat-label">Enabled</div>
        <div class="stat-value">
          {providers.filter((p) => p.enabled).length}<span class="unit">/ {providers.length}</span>
        </div>
        <div class="stat-sub">providers currently active</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Entrypoints</div>
        <div class="stat-value">
          {providers.reduce((acc, p) => acc + p.entrypoint_count, 0)}
        </div>
        <div class="stat-sub">across every provider</div>
      </div>
    </section>
  {/snippet}

  {#snippet row(p: Provider)}
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
  {/snippet}
</ResourceTable>

<style>
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

  /* Cell rules stay here: the `row` snippet is compiled into this page, so its
   * <td>s carry this component's scope, not ResourceTable's. */
  td {
    text-align: left;
    padding: 0.7rem 1rem;
    font-size: 0.85rem;
    border-bottom: 1px solid var(--border);
  }
  td.num {
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
</style>
