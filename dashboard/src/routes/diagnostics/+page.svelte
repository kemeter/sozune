<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { goto } from '$app/navigation';
  import {
    listDiagnostics,
    listEntrypoints,
    type Diagnostic,
    type DiagnosticsResponse,
    type Entrypoint
  } from '$lib/api';
  import { isAuthenticated } from '$lib/auth';

  let data = $state<DiagnosticsResponse | null>(null);
  /** Loaded alongside diagnostics so we can drill down from a candidate to the
   *  entrypoint(s) it produced. Lookup uses both `entrypoint.id` and
   *  `entrypoint.source` since providers attribute differently. */
  let entrypoints = $state<Entrypoint[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let lastRefresh = $state<Date | null>(null);

  type SeverityFilter = 'all' | 'error' | 'warn' | 'info';

  /** Read a query param with a default. Safe before mount (SSR returns the
   *  fallback). */
  function getParam(key: string, fallback: string): string {
    if (typeof window === 'undefined') return fallback;
    const v = new URL(window.location.href).searchParams.get(key);
    return v ?? fallback;
  }

  /** Filter state is driven by the URL so links can deep-link a pre-filtered
   *  view (e.g. /diagnostics?code=W009) and reload/share keeps filters. */
  let severityFilter = $state<SeverityFilter>(getParam('severity', 'all') as SeverityFilter);
  let codeFilter = $state<string>(getParam('code', 'all'));
  let search = $state<string>(getParam('q', ''));

  let poll: ReturnType<typeof setInterval> | null = null;

  /** Push the current filter state back into the URL. `replaceState` keeps
   *  the back button useful (goes to the previous page, not to each filter
   *  toggle in between). */
  function syncUrl() {
    if (typeof window === 'undefined') return;
    const url = new URL(window.location.href);
    const params = url.searchParams;

    const writeOrClear = (key: string, value: string, def: string) => {
      if (value === def || value === '') params.delete(key);
      else params.set(key, value);
    };

    writeOrClear('severity', severityFilter, 'all');
    writeOrClear('code', codeFilter, 'all');
    writeOrClear('q', search, '');

    const next = url.pathname + (params.toString() ? `?${params}` : '');
    if (next !== url.pathname + url.search) {
      void goto(next, { replaceState: true, keepFocus: true, noScroll: true });
    }
  }

  $effect(() => {
    severityFilter;
    codeFilter;
    search;
    syncUrl();
  });

  const stats = $derived.by(() => {
    if (!data) return { total: 0, error: 0, warn: 0, info: 0 };
    const all = [...(data.global ?? []), ...data.items.flatMap((i) => i.diagnostics)];
    return {
      total: all.length,
      error: all.filter((d) => d.severity === 'error').length,
      warn: all.filter((d) => d.severity === 'warn').length,
      info: all.filter((d) => d.severity === 'info').length
    };
  });

  /** All diagnostic codes seen in the current snapshot, sorted, for the dropdown. */
  const codes = $derived.by(() => {
    if (!data) return ['all'];
    const set = new Set<string>();
    for (const d of data.global ?? []) set.add(d.code);
    for (const it of data.items) for (const d of it.diagnostics) set.add(d.code);
    return ['all', ...Array.from(set).sort()];
  });

  function passes(d: Diagnostic, candidateId?: string): boolean {
    if (severityFilter !== 'all' && d.severity !== severityFilter) return false;
    if (codeFilter !== 'all' && d.code !== codeFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      const haystack = [
        d.code,
        d.message,
        d.label ?? '',
        d.value ?? '',
        d.hint ?? '',
        candidateId ?? ''
      ]
        .join('|')
        .toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  }

  const filteredItems = $derived(
    (data?.items ?? [])
      .map((i) => ({
        ...i,
        diagnostics: i.diagnostics.filter((d) => passes(d, i.candidate_id))
      }))
      .filter((i) => i.diagnostics.length > 0)
  );

  const filteredGlobal = $derived((data?.global ?? []).filter((d) => passes(d)));

  const hasActiveSecondaryFilters = $derived(
    codeFilter !== 'all' || severityFilter !== 'all' || search !== ''
  );

  function resetFilters() {
    severityFilter = 'all';
    codeFilter = 'all';
    search = '';
  }

  /** Resolve the entrypoints linked to a given candidate id. The diagnostics
   *  store keys on candidate id, while runtime entrypoints carry that id
   *  either in `entrypoint.id` (Sōzu cluster_id when the candidate is the
   *  unique source) or in `entrypoint.source` (when providers post-process). */
  function entrypointsFor(candidateId: string): Entrypoint[] {
    return entrypoints.filter(
      (ep) => ep.id === candidateId || ep.source === candidateId
    );
  }

  async function load(silent = false) {
    if (!silent) loading = true;
    try {
      const [d, eps] = await Promise.all([listDiagnostics(), listEntrypoints()]);
      data = d;
      entrypoints = eps;
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
  <div class="search">
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="7" cy="7" r="5"/><path d="M11 11l3 3" stroke-linecap="round"/></svg>
    <input type="text" placeholder="search by code, message, label, candidate…" bind:value={search} />
  </div>
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
  <label class="select-wrap">
    <span class="select-label">Code</span>
    <select bind:value={codeFilter}>
      {#each codes as c}
        <option value={c}>{c}</option>
      {/each}
    </select>
  </label>
  {#if hasActiveSecondaryFilters}
    <button class="reset-btn" onclick={resetFilters}>Reset</button>
  {/if}
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
      {#if entrypointsFor(item.candidate_id).length > 0}
        <div class="group-eps">
          <span class="group-eps-label">Affected entrypoints:</span>
          {#each entrypointsFor(item.candidate_id) as ep}
            <a
              class="ep-chip mono"
              href={`/entrypoints/${encodeURIComponent(ep.id)}`}
            >{ep.name || ep.id}</a>
          {/each}
        </div>
      {/if}
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
      <button
        type="button"
        class="diag-code mono"
        class:active={codeFilter === diag.code}
        title={codeFilter === diag.code ? 'Clear filter' : `Filter by ${diag.code}`}
        onclick={() => (codeFilter = codeFilter === diag.code ? 'all' : diag.code)}
      >{diag.code}</button>
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
    border: 1px solid transparent;
    cursor: pointer;
    transition: background 120ms ease, color 120ms ease, border-color 120ms ease;
  }
  .diag-code:hover {
    background: var(--bg-hover);
    color: var(--fg-0);
  }
  .diag-code.active {
    background: var(--accent-bg);
    color: var(--accent);
    border-color: var(--accent);
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

  .toolbar {
    display: flex;
    gap: 0.625rem;
    margin-bottom: 1rem;
    align-items: center;
    flex-wrap: wrap;
  }
  .search {
    flex: 1;
    min-width: 220px;
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
    padding: 0.5rem 0.75rem 0.5rem 2.1rem;
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--fg-0);
    outline: none;
  }
  .search input:focus {
    border-color: var(--accent);
  }
  .search input::placeholder {
    color: var(--fg-3);
  }
  .select-wrap {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 4px 8px 4px 10px;
  }
  .select-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--fg-2);
    font-weight: 500;
  }
  .select-wrap select {
    background: transparent;
    border: none;
    color: var(--fg-0);
    font-size: 0.78rem;
    outline: none;
    padding: 2px 4px;
    cursor: pointer;
  }
  .select-wrap select option {
    background: var(--bg-1);
    color: var(--fg-0);
  }
  .reset-btn {
    background: transparent;
    border: 1px dashed var(--border);
    color: var(--fg-2);
    border-radius: var(--radius);
    padding: 0.4rem 0.75rem;
    font-size: 0.72rem;
    cursor: pointer;
  }
  .reset-btn:hover {
    color: var(--fg-0);
    border-style: solid;
  }

  .group-eps {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    margin: 0 0 0.5rem;
    font-size: 0.75rem;
  }
  .group-eps-label {
    color: var(--fg-3);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-size: 0.65rem;
    font-weight: 500;
    margin-right: 4px;
  }
  .ep-chip {
    background: var(--bg-3);
    color: var(--fg-1);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.72rem;
    text-decoration: none;
    border: 1px solid transparent;
    transition: border-color 0.1s, color 0.1s;
  }
  .ep-chip:hover {
    color: var(--fg-0);
    border-color: var(--accent);
  }
</style>
