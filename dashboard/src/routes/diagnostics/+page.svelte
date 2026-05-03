<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { goto } from '$app/navigation';
  import { listDiagnostics, type Diagnostic, type DiagnosticsResponse } from '$lib/api';
  import { isAuthenticated } from '$lib/auth';

  let data = $state<DiagnosticsResponse | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let lastRefresh = $state<Date | null>(null);
  let severityFilter = $state<'all' | 'error' | 'warn' | 'info'>('all');

  let poll: ReturnType<typeof setInterval> | null = null;

  const stats = $derived.by(() => {
    if (!data) return { total: 0, error: 0, warn: 0, info: 0 };
    const all = [...data.global, ...data.items.flatMap((i) => i.diagnostics)];
    return {
      total: all.length,
      error: all.filter((d) => d.severity === 'error').length,
      warn: all.filter((d) => d.severity === 'warn').length,
      info: all.filter((d) => d.severity === 'info').length
    };
  });

  function passes(d: Diagnostic): boolean {
    return severityFilter === 'all' || d.severity === severityFilter;
  }

  const filteredItems = $derived(
    (data?.items ?? [])
      .map((i) => ({ ...i, diagnostics: i.diagnostics.filter(passes) }))
      .filter((i) => i.diagnostics.length > 0)
  );

  const filteredGlobal = $derived((data?.global ?? []).filter(passes));

  async function load(silent = false) {
    if (!silent) loading = true;
    try {
      data = await listDiagnostics();
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
    <h1>Diagnostics</h1>
    <p class="subtitle">Issues detected by the label parser and the config lints</p>
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
    <div class="stat-label">Total</div>
    <div class="stat-value">{stats.total}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Errors</div>
    <div class="stat-value sev-error">{stats.error}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Warnings</div>
    <div class="stat-value sev-warn">{stats.warn}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Info</div>
    <div class="stat-value sev-info">{stats.info}</div>
  </div>
</section>

<section class="toolbar">
  <div class="filters">
    {#each ['all', 'error', 'warn', 'info'] as sev}
      <button
        class="filter-chip"
        class:active={severityFilter === sev}
        onclick={() => (severityFilter = sev as typeof severityFilter)}
      >
        {sev}
      </button>
    {/each}
  </div>
</section>

{#if error}
  <div class="alert">
    <strong>error</strong> {error}
  </div>
{/if}

{#if loading && !data}
  <div class="empty">loading…</div>
{:else if stats.total === 0}
  <div class="empty">no diagnostics — every entrypoint parsed cleanly</div>
{:else}
  {#if filteredGlobal.length > 0}
    <section class="group">
      <h2 class="group-title">Global</h2>
      <div class="diag-list">
        {#each filteredGlobal as diag}
          {@render diagCard(diag)}
        {/each}
      </div>
    </section>
  {/if}

  {#each filteredItems as item}
    <section class="group">
      <h2 class="group-title">
        <span class="group-id mono">{item.candidate_id}</span>
        <span class="group-count">{item.diagnostics.length}</span>
      </h2>
      <div class="diag-list">
        {#each item.diagnostics as diag}
          {@render diagCard(diag)}
        {/each}
      </div>
    </section>
  {/each}
{/if}

{#snippet diagCard(diag: Diagnostic)}
  <div class="diag diag-{diag.severity}">
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
  </div>
{/snippet}

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
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.5rem 0.875rem;
    font-size: 0.8rem;
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
  .sev-error { color: var(--danger); }
  .sev-warn { color: var(--warning); }
  .sev-info { color: var(--accent); }

  .toolbar {
    margin-bottom: 1rem;
  }
  .filters {
    display: inline-flex;
    gap: 4px;
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 3px;
  }
  .filter-chip {
    padding: 0.35rem 0.85rem;
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
  }

  .empty {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 2.5rem;
    text-align: center;
    color: var(--fg-3);
    font-size: 0.85rem;
  }

  .group {
    margin-bottom: 1.5rem;
  }
  .group-title {
    font-size: 0.825rem;
    font-weight: 500;
    color: var(--fg-2);
    margin: 0 0 0.5rem;
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }
  .group-id {
    color: var(--fg-1);
    word-break: break-all;
  }
  .group-count {
    background: var(--bg-3);
    color: var(--fg-2);
    font-size: 0.7rem;
    font-weight: 500;
    padding: 1px 7px;
    border-radius: 999px;
  }

  .diag-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .diag {
    border: 1px solid var(--border);
    border-left-width: 3px;
    border-radius: var(--radius);
    padding: 0.625rem 0.875rem;
    background: var(--bg-1);
  }
  .diag-error { border-left-color: var(--danger); }
  .diag-warn { border-left-color: var(--warning); }
  .diag-info { border-left-color: var(--accent); }
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
  .diag-error .diag-glyph { color: var(--danger); }
  .diag-warn .diag-glyph { color: var(--warning); }
  .diag-info .diag-glyph { color: var(--accent); }
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
  .diag-value { color: var(--fg-2); }
  .diag-hint {
    color: var(--fg-2);
    font-size: 0.78rem;
    margin-top: 0.35rem;
    margin-left: 1.45rem;
  }
</style>
