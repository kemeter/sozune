<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { goto } from '$app/navigation';
  import { listEntrypoints, type Entrypoint } from '$lib/api';
  import { isAuthenticated } from '$lib/auth';

  let entrypoints = $state<Entrypoint[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let poll: ReturnType<typeof setInterval> | null = null;

  type CertStatus = 'valid' | 'expiring' | 'expired';

  interface Cert {
    /** Common name (primary host). */
    cn: string;
    /** Other hostnames on the same cert (SAN — minus the CN). */
    san: string[];
    issuer: string;
    issuedAt: Date;
    expiresAt: Date;
    serial: string;
    keyType: string;
    /** Where the cert came from: ACME (auto-renewed) or a static file path. */
    source: 'acme' | 'file';
    sourceLabel: string;
    /** Which entrypoint(s) serve this cert. Empty if cert exists but no
     *  route references it (orphan). */
    entrypoints: string[];
  }

  /** Mock certificate inventory until `GET /certificates` lands. Mixes valid,
   *  expiring soon, and expired so the UI can demo every state. Dates are
   *  computed from `now` so the demo always looks live. */
  const certs = $derived.by<Cert[]>(() => {
    const now = new Date();
    const days = (n: number) => {
      const d = new Date(now);
      d.setDate(d.getDate() + n);
      return d;
    };
    return [
      {
        cn: 'shop.demo.localhost',
        san: [],
        issuer: "Let's Encrypt R3",
        issuedAt: days(-23),
        expiresAt: days(67),
        serial: '04:8d:e9:14:0e:1c:c7:b1:c9:5b',
        keyType: 'ECDSA P-256',
        source: 'acme',
        sourceLabel: 'acme · letsencrypt',
        entrypoints: ['Shop Frontend']
      },
      {
        cn: 'api.demo.localhost',
        san: ['api-v2.demo.localhost'],
        issuer: "Let's Encrypt R3",
        issuedAt: days(-67),
        expiresAt: days(23),
        serial: '03:b9:2e:81:7c:42:8e:0a:1f:64',
        keyType: 'ECDSA P-256',
        source: 'acme',
        sourceLabel: 'acme · letsencrypt',
        entrypoints: ['Public API']
      },
      {
        cn: 'blog.demo.localhost',
        san: [],
        issuer: "Let's Encrypt R3",
        issuedAt: days(-88),
        expiresAt: days(2),
        serial: '04:b1:5e:0c:71:35:a4:f2:c8:de',
        keyType: 'RSA 2048',
        source: 'acme',
        sourceLabel: 'acme · letsencrypt',
        entrypoints: ['Blog']
      },
      {
        cn: 'admin.demo.localhost',
        san: [],
        issuer: 'Internal CA — kemeter',
        issuedAt: days(-180),
        expiresAt: days(185),
        serial: '7f:ab:09:1c:55:9a:e4:12:00:88',
        keyType: 'RSA 4096',
        source: 'file',
        sourceLabel: 'file · /etc/sozune/certs/admin.pem',
        entrypoints: ['Admin Portal']
      },
      {
        cn: 'legacy.demo.localhost',
        san: [],
        issuer: 'DigiCert TLS RSA SHA256 2020 CA1',
        issuedAt: days(-410),
        expiresAt: days(-45),
        serial: '0a:1b:2c:3d:4e:5f:60:71:82:93',
        keyType: 'RSA 2048',
        source: 'file',
        sourceLabel: 'file · /etc/sozune/certs/legacy.pem',
        entrypoints: []
      },
      {
        cn: '*.lab.demo.localhost',
        san: [],
        issuer: "Let's Encrypt R3",
        issuedAt: days(-12),
        expiresAt: days(78),
        serial: '04:c3:7d:e9:14:0e:8b:af:5c:21',
        keyType: 'ECDSA P-256',
        source: 'acme',
        sourceLabel: 'acme · letsencrypt (DNS-01)',
        entrypoints: ['lab', 'sandbox']
      }
    ];
  });

  function daysLeft(c: Cert): number {
    const ms = c.expiresAt.getTime() - Date.now();
    return Math.ceil(ms / (1000 * 60 * 60 * 24));
  }

  function statusOf(c: Cert): CertStatus {
    const d = daysLeft(c);
    if (d < 0) return 'expired';
    if (d <= 30) return 'expiring';
    return 'valid';
  }

  function fmtDate(d: Date): string {
    return d.toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  }

  function fmtRelative(c: Cert): string {
    const d = daysLeft(c);
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

  const stats = $derived({
    total: certs.length,
    valid: certs.filter((c) => statusOf(c) === 'valid').length,
    expiring: certs.filter((c) => statusOf(c) === 'expiring').length,
    expired: certs.filter((c) => statusOf(c) === 'expired').length,
    acme: certs.filter((c) => c.source === 'acme').length
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
        <th>Issuer</th>
        <th>Expires</th>
        <th>Source</th>
        <th>Entrypoints</th>
      </tr>
    </thead>
    <tbody>
      {#each certs as cert (cert.serial)}
        {@const status = statusOf(cert)}
        <tr class="row-{status}">
          <td>
            <span class="badge badge-{status}">
              <span class="dot dot-{status}"></span>
              {status}
            </span>
          </td>
          <td>
            <div class="cn mono">{cert.cn}</div>
            {#if cert.san.length > 0}
              <div class="san">
                + {cert.san.length} SAN{cert.san.length > 1 ? 's' : ''} ·
                <span class="mono">{cert.san.join(', ')}</span>
              </div>
            {/if}
            <div class="meta">
              <span class="key-type">{cert.keyType}</span>
              <span class="dot-sep">·</span>
              <span class="serial mono" title="Serial number">SN {cert.serial.slice(0, 11)}…</span>
            </div>
          </td>
          <td>
            <div>{cert.issuer}</div>
            <div class="meta">issued {fmtDate(cert.issuedAt)}</div>
          </td>
          <td>
            <div class="mono">{fmtDate(cert.expiresAt)}</div>
            <div class="meta meta-{status}">{fmtRelative(cert)}</div>
          </td>
          <td>
            <span class="badge badge-source badge-source-{cert.source}">{cert.source}</span>
            <div class="meta source-detail mono">{cert.sourceLabel.replace(/^acme · |^file · /, '')}</div>
          </td>
          <td>
            {#if cert.entrypoints.length === 0}
              <span class="muted">— no route</span>
            {:else}
              <div class="chips">
                {#each cert.entrypoints as ep}
                  <span class="chip">{ep}</span>
                {/each}
              </div>
            {/if}
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

  .badge-source {
    background: var(--bg-3);
    color: var(--fg-1);
  }
  .badge-source-acme {
    color: var(--accent);
    background: var(--accent-bg);
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
  .dot-sep {
    margin: 0 4px;
    opacity: 0.5;
  }
  .key-type {
    color: var(--fg-2);
  }
  .source-detail {
    font-size: 0.68rem;
    color: var(--fg-3);
    margin-top: 4px;
    word-break: break-all;
  }

  .muted {
    color: var(--fg-3);
    font-size: 0.78rem;
  }
</style>
