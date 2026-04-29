<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { goto } from '$app/navigation';
  import { listEntrypoints, type Entrypoint } from '$lib/api';
  import { isAuthenticated } from '$lib/auth';

  let entrypoints = $state<Entrypoint[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let poll: ReturnType<typeof setInterval> | null = null;

  interface HostRow {
    hostname: string;
    entrypoints: string[];
    httpsRedirect: boolean;
  }

  const tlsHosts = $derived.by<HostRow[]>(() => {
    const map = new Map<string, HostRow>();
    for (const ep of entrypoints) {
      if (!ep.config.tls) continue;
      for (const host of ep.config.hostnames) {
        const existing = map.get(host);
        if (existing) {
          existing.entrypoints.push(ep.name);
          existing.httpsRedirect ||= !!ep.config.https_redirect;
        } else {
          map.set(host, {
            hostname: host,
            entrypoints: [ep.name],
            httpsRedirect: !!ep.config.https_redirect
          });
        }
      }
    }
    return [...map.values()].sort((a, b) => a.hostname.localeCompare(b.hostname));
  });

  const stats = $derived({
    tlsHosts: tlsHosts.length,
    tlsEntrypoints: entrypoints.filter((e) => e.config.tls).length,
    redirects: entrypoints.filter((e) => e.config.https_redirect).length
  });

  async function load(silent = false) {
    if (!silent) loading = true;
    try {
      entrypoints = await listEntrypoints();
      error = null;
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
    poll = setInterval(() => void load(true), 10000);
  });

  onDestroy(() => {
    if (poll) clearInterval(poll);
  });
</script>

<header class="page-header">
  <div>
    <h1>Certificates</h1>
    <p class="subtitle">TLS hosts served by the proxy</p>
  </div>
</header>

<section class="stats">
  <div class="stat-card">
    <div class="stat-label">TLS hosts</div>
    <div class="stat-value">{stats.tlsHosts}</div>
    <div class="stat-sub">unique hostnames served over TLS</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">TLS entrypoints</div>
    <div class="stat-value">{stats.tlsEntrypoints}</div>
    <div class="stat-sub">entrypoints with tls enabled</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">HTTPS redirects</div>
    <div class="stat-value">{stats.redirects}</div>
    <div class="stat-sub">entrypoints forcing https</div>
  </div>
</section>

<div class="notice">
  <strong>heads up</strong>
  Certificate introspection (issuer, expiry, ACME state) will land once the API
  exposes <code>GET /certificates</code>. For now, this view lists hosts derived
  from TLS-enabled entrypoints.
</div>

{#if error}
  <div class="alert">
    <strong>error</strong> {error}
  </div>
{/if}

<section class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Hostname</th>
        <th>Entrypoints</th>
        <th>HTTPS redirect</th>
        <th>Source</th>
      </tr>
    </thead>
    <tbody>
      {#if loading && entrypoints.length === 0}
        <tr><td colspan="4" class="empty">loading…</td></tr>
      {:else if tlsHosts.length === 0}
        <tr><td colspan="4" class="empty">no TLS hosts configured</td></tr>
      {:else}
        {#each tlsHosts as row (row.hostname)}
          <tr>
            <td class="mono">{row.hostname}</td>
            <td>
              <div class="chips">
                {#each row.entrypoints as ep}
                  <span class="chip">{ep}</span>
                {/each}
              </div>
            </td>
            <td>
              {#if row.httpsRedirect}
                <span class="badge ok">enabled</span>
              {:else}
                <span class="muted">—</span>
              {/if}
            </td>
            <td class="mono source">ACME / staging</td>
          </tr>
        {/each}
      {/if}
    </tbody>
  </table>
</section>

<style>
  .page-header {
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

  .stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
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
  .stat-sub {
    font-size: 0.75rem;
    color: var(--fg-3);
    margin-top: 0.25rem;
  }

  .notice {
    background: var(--accent-bg);
    border: 1px solid rgba(91, 141, 255, 0.3);
    color: var(--fg-1);
    padding: 0.75rem 1rem;
    border-radius: var(--radius);
    margin-bottom: 1.25rem;
    font-size: 0.8rem;
    line-height: 1.55;
  }
  .notice strong {
    color: var(--accent);
    margin-right: 0.5rem;
    text-transform: uppercase;
    font-size: 0.68rem;
    letter-spacing: 0.08em;
  }
  .notice code {
    background: var(--bg-3);
    padding: 1px 5px;
    border-radius: 3px;
    font-family: var(--font-mono);
    font-size: 0.78rem;
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
  tbody tr:hover {
    background: var(--bg-2);
  }

  .empty {
    text-align: center;
    color: var(--fg-3);
    padding: 2rem !important;
  }

  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .chip {
    background: var(--bg-3);
    color: var(--fg-1);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.72rem;
    font-family: var(--font-mono);
  }

  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    font-family: var(--font-mono);
    text-transform: uppercase;
  }
  .badge.ok {
    background: var(--success-bg);
    color: var(--success);
  }

  .muted {
    color: var(--fg-3);
  }

  .source {
    color: var(--fg-3);
    font-size: 0.72rem;
  }
</style>
