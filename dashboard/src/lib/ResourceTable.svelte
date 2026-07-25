<script lang="ts" generics="T">
  /**
   * The list-page shell shared by the resource listings: page header with an
   * optional refresh control, error and empty states, and the table itself —
   * plus the load-and-poll lifecycle.
   *
   * Pages own their columns and cells (via the `row` snippet) and anything
   * specific that sits between the header and the table (stat cards, filters)
   * via the `beforeTable` snippet. Everything that was duplicated verbatim
   * across the listing pages lives here instead.
   */
  import { onDestroy, onMount } from 'svelte';
  import type { Snippet } from 'svelte';

  interface Props {
    title: string;
    subtitle: string;
    /** Column headers, in order. `align: 'right'` gets tabular numerals. */
    columns: Array<{ label: string; align?: 'right' }>;
    /** Fetches the full list; re-run on refresh and on every poll tick. */
    load: () => Promise<T[]>;
    /** Stable key per item, for keyed `{#each}`. */
    key: (item: T) => string;
    /** Poll interval in ms; `0` disables polling. */
    pollMs?: number;
    /** Show the header's Refresh button and "updated …" marker. */
    refreshable?: boolean;
    /** One `<tr>` per item. */
    row: Snippet<[T]>;
    /** Text shown when the list comes back empty. */
    emptyText?: string;
    /** Rendered between the header and the table — stat cards, filters, … */
    beforeTable?: Snippet<[T[]]>;
  }

  let {
    title,
    subtitle,
    columns,
    load,
    key,
    pollMs = 5000,
    refreshable = true,
    row,
    emptyText = 'Nothing to show.',
    beforeTable
  }: Props = $props();

  let items = $state<T[]>([]);
  let loading = $state(true);
  let errorMsg = $state<string | null>(null);
  let lastFetch = $state<Date | null>(null);
  let poll: ReturnType<typeof setInterval> | null = null;

  export async function refresh(): Promise<void> {
    try {
      items = await load();
      errorMsg = null;
    } catch (e) {
      errorMsg = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
      lastFetch = new Date();
    }
  }

  function timeAgo(d: Date | null): string {
    if (!d) return '';
    const s = Math.floor((Date.now() - d.getTime()) / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return `${s}s ago`;
    return `${Math.floor(s / 60)}m ago`;
  }

  onMount(() => {
    void refresh();
    if (pollMs > 0) {
      poll = setInterval(() => void refresh(), pollMs);
    }
  });

  onDestroy(() => {
    if (poll) {
      clearInterval(poll);
    }
  });
</script>

<header class="page-header">
  <div>
    <h1>{title}</h1>
    <p class="subtitle">{subtitle}</p>
  </div>
  {#if refreshable}
    <div class="header-actions">
      {#if lastFetch}
        <span class="refresh-meta">updated {timeAgo(lastFetch)}</span>
      {/if}
      <button class="btn-secondary" onclick={refresh} disabled={loading}>
        {loading ? 'loading…' : 'Refresh'}
      </button>
    </div>
  {/if}
</header>

{#if beforeTable}
  {@render beforeTable(items)}
{/if}

{#if errorMsg}
  <div class="alert">
    <strong>error</strong>
    {errorMsg}
  </div>
{/if}

{#if !loading && items.length > 0}
  <section class="card">
    <table>
      <thead>
        <tr>
          {#each columns as col}
            <th class:num={col.align === 'right'}>{col.label}</th>
          {/each}
        </tr>
      </thead>
      <tbody>
        {#each items as item (key(item))}
          {@render row(item)}
        {/each}
      </tbody>
    </table>
  </section>
{/if}

{#if !loading && items.length === 0 && !errorMsg}
  <div class="empty">{emptyText}</div>
{/if}

<style>
  /* These primitives live in each page's own <style> rather than app.css, so
   * the component carries the shape it renders. Svelte scopes both sides, and
   * a page keeps whatever it still defines locally for its own markup. */
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
  th {
    text-align: left;
    padding: 0.7rem 1rem;
    border-bottom: 1px solid var(--border);
    font-weight: 500;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--fg-2);
    background: var(--bg-0);
  }
  th.num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  /* Both the <tr> and its <td>s come from the caller's `row` snippet, so they
   * carry the page's scope rather than this component's — a scoped selector
   * here would match nothing and be pruned. Only this last-row border needs to
   * reach into the snippet; every other cell rule stays with the page that
   * renders the cells. */
  tbody :global(tr:last-child td) {
    border-bottom: none;
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
