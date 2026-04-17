<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { health, getBaseUrl } from '$lib/api';

  type Status = 'pending' | 'ok' | 'fail';

  let status = $state<Status>('pending');
  let payload = $state<unknown>(null);
  let errorMsg = $state<string | null>(null);
  let lastCheck = $state<Date | null>(null);
  let latencyMs = $state<number | null>(null);

  let poll: ReturnType<typeof setInterval> | null = null;

  async function check() {
    const started = performance.now();
    try {
      payload = await health();
      latencyMs = Math.round(performance.now() - started);
      status = 'ok';
      errorMsg = null;
    } catch (e) {
      status = 'fail';
      latencyMs = null;
      errorMsg = e instanceof Error ? e.message : String(e);
      payload = null;
    } finally {
      lastCheck = new Date();
    }
  }

  onMount(() => {
    void check();
    poll = setInterval(() => void check(), 5000);
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
    <h1>Health</h1>
    <p class="subtitle">Liveness of the sozune admin API</p>
  </div>
  <div class="header-actions">
    {#if lastCheck}
      <span class="refresh-meta">checked {timeAgo(lastCheck)}</span>
    {/if}
    <button class="btn-secondary" onclick={check} disabled={status === 'pending'}>
      {status === 'pending' ? 'checking…' : 'Refresh'}
    </button>
  </div>
</header>

<section class="stats">
  <div class="stat-card">
    <div class="stat-label">Status</div>
    <div class="stat-value" class:ok={status === 'ok'} class:fail={status === 'fail'}>
      {#if status === 'ok'}
        <span class="dot ok"></span> healthy
      {:else if status === 'fail'}
        <span class="dot fail"></span> unreachable
      {:else}
        <span class="dot pending"></span> checking
      {/if}
    </div>
    <div class="stat-sub">polling every 5s</div>
  </div>

  <div class="stat-card">
    <div class="stat-label">Latency</div>
    <div class="stat-value mono">
      {#if latencyMs !== null}
        {latencyMs}<span class="unit">ms</span>
      {:else}
        —
      {/if}
    </div>
    <div class="stat-sub">round-trip to /health</div>
  </div>

  <div class="stat-card wide">
    <div class="stat-label">Endpoint</div>
    <div class="stat-value mono small">{getBaseUrl()}/health</div>
    <div class="stat-sub">from your browser</div>
  </div>
</section>

{#if status === 'fail' && errorMsg}
  <div class="alert">
    <strong>error</strong> {errorMsg}
    <p class="alert-hint">
      Check that sozune is running, the API is enabled, and the base URL in
      <a href="./settings">Settings</a> is correct.
    </p>
  </div>
{/if}

{#if status === 'ok' && payload !== null && payload !== undefined}
  <section class="card">
    <h2>Response payload</h2>
    <pre class="mono">{JSON.stringify(payload, null, 2)}</pre>
  </section>
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
  .stat-card.wide {
    grid-column: span 2;
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
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .stat-value.small {
    font-size: 0.85rem;
    font-weight: 500;
    color: var(--fg-1);
    word-break: break-all;
  }
  .stat-value.ok {
    color: var(--success);
  }
  .stat-value.fail {
    color: var(--danger);
  }
  .unit {
    font-size: 0.85rem;
    color: var(--fg-2);
    font-weight: 500;
    margin-left: 2px;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }
  .dot.ok {
    background: var(--success);
    box-shadow: 0 0 0 3px var(--success-bg);
    animation: pulse 2s infinite;
  }
  .dot.fail {
    background: var(--danger);
    box-shadow: 0 0 0 3px var(--danger-bg);
  }
  .dot.pending {
    background: var(--fg-2);
    box-shadow: 0 0 0 3px rgba(122, 133, 148, 0.18);
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
  .alert-hint {
    margin: 0.5rem 0 0;
    color: var(--fg-2);
    font-size: 0.78rem;
  }

  .card {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.25rem 1.5rem;
  }
  .card h2 {
    margin: 0 0 0.75rem;
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--fg-1);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  pre {
    margin: 0;
    padding: 0.75rem 0.9rem;
    background: var(--bg-0);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    font-size: 0.78rem;
    color: var(--fg-1);
    overflow-x: auto;
    line-height: 1.55;
  }
</style>
