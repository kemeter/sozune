<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { goto } from '$app/navigation';
  import { listCertificates, type Certificate, type CertStatus } from '$lib/api';
  import { isAuthenticated } from '$lib/auth';

  let certs = $state<Certificate[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let poll: ReturnType<typeof setInterval> | null = null;

  function fmtDate(epochSeconds: number): string {
    return new Date(epochSeconds * 1000).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  }

  /** Human-friendly remaining lifetime, from the server-computed day count. */
  function fmtRelative(c: Certificate): string {
    const d = c.remaining_days;
    if (d < 0) return `expired ${-d} d ago`;
    if (d === 0) return 'expires today';
    if (d === 1) return 'expires in 1 day';
    if (d < 60) return `${d} days left`;
    if (d < 730) {
      const m = Math.round(d / 30);
      return `${m} months left`;
    }
    const y = Math.round(d / 365);
    return `${y} years left`;
  }

  /** SANs other than the one already shown as the primary name, so the row
   *  doesn't repeat the hostname. */
  function extraSans(c: Certificate): string[] {
    const primary = c.subject_cn ?? c.hostname;
    return c.sans.filter((s) => s !== primary);
  }

  const stats = $derived({
    total: certs.length,
    valid: certs.filter((c) => c.status === 'valid').length,
    expiring: certs.filter((c) => c.status === 'expiring').length,
    expired: certs.filter((c) => c.status === 'expired').length
  });

  async function load(silent = false) {
    if (!silent) loading = true;
    try {
      certs = (await listCertificates()).certificates;
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
    <p class="subtitle">TLS certificates served by the proxy</p>
  </div>
</header>

<section class="stats">
  <div class="stat-card">
    <div class="stat-label">Total</div>
    <div class="stat-value">{stats.total}</div>
    <div class="stat-sub">certificates loaded</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Valid</div>
    <div class="stat-value sev-ok">{stats.valid}</div>
    <div class="stat-sub">expire in &gt; 30 days</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Expiring soon</div>
    <div class="stat-value sev-warn">{stats.expiring}</div>
    <div class="stat-sub">expire in &lt; 30 days</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Expired</div>
    <div class="stat-value sev-err">{stats.expired}</div>
    <div class="stat-sub">no longer valid</div>
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
        <th>Status</th>
        <th>Common name</th>
        <th>Expires</th>
        <th>Lifetime</th>
      </tr>
    </thead>
    <tbody>
      {#if !loading && certs.length === 0}
        <tr>
          <td colspan="4" class="empty">No certificates on disk.</td>
        </tr>
      {/if}
      {#each certs as cert (cert.hostname)}
        {@const sans = extraSans(cert)}
        <tr class="row-{cert.status}">
          <td>
            <span class="badge badge-{cert.status}">
              <span class="dot dot-{cert.status}"></span>
              {cert.status}
            </span>
          </td>
          <td>
            <div class="cn mono">{cert.subject_cn ?? cert.hostname}</div>
            {#if sans.length > 0}
              <div class="san">
                + {sans.length} SAN{sans.length > 1 ? 's' : ''} ·
                <span class="mono">{sans.join(', ')}</span>
              </div>
            {/if}
          </td>
          <td>
            <div class="mono">{fmtDate(cert.not_after)}</div>
            <div class="meta meta-{cert.status}">{fmtRelative(cert)}</div>
          </td>
          <td>
            <div>{cert.total_days} days</div>
            <div class="meta">issued {fmtDate(cert.not_before)}</div>
          </td>
        </tr>
      {/each}
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
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 1.5rem;
  }
  .stat-value.sev-ok { color: var(--success); }
  .stat-value.sev-warn { color: var(--warning); }
  .stat-value.sev-err { color: var(--danger); }
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

  .badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }
  .badge-valid {
    background: var(--success-bg);
    color: var(--success);
  }
  .badge-expiring {
    background: var(--warning-bg);
    color: var(--warning);
  }
  .badge-expired {
    background: var(--danger-bg);
    color: var(--danger);
  }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
  }
  .dot-valid { background: var(--success); }
  .dot-expiring {
    background: var(--warning);
    animation: pulse-warn 2s infinite;
  }
  .dot-expired { background: var(--danger); }
  @keyframes pulse-warn {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  .row-expired td {
    background: rgba(248, 81, 73, 0.04);
  }
  .row-expiring td {
    background: rgba(240, 180, 41, 0.03);
  }

  .cn {
    font-size: 0.875rem;
    color: var(--fg-0);
  }
  .san {
    font-size: 0.72rem;
    color: var(--fg-2);
    margin-top: 2px;
  }
  .meta {
    font-size: 0.7rem;
    color: var(--fg-3);
    margin-top: 3px;
  }
  .meta-valid { color: var(--success); }
  .meta-expiring {
    color: var(--warning);
    font-weight: 500;
  }
  .meta-expired {
    color: var(--danger);
    font-weight: 500;
  }
</style>
