<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { goto } from '$app/navigation';
  import {
    listEntrypoints,
    listDiagnostics,
    listProviders,
    getBaseUrl,
    type Entrypoint,
    type Provider,
    type Diagnostic
  } from '$lib/api';
  import { isAuthenticated } from '$lib/auth';

  let entrypoints = $state<Entrypoint[]>([]);
  let providers = $state<Provider[]>([]);
  let globalDiagnostics = $state<Diagnostic[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let lastRefresh = $state<Date | null>(null);
  let poll: ReturnType<typeof setInterval> | null = null;

  async function load(silent = false) {
    if (!silent) loading = true;
    try {
      const [eps, prov, diag] = await Promise.all([
        listEntrypoints(),
        listProviders(),
        listDiagnostics()
      ]);
      entrypoints = eps;
      providers = prov.providers ?? [];
      globalDiagnostics = diag.global ?? [];
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

  /** Listener inventory. The API listener is authoritative (we know its URL).
   *  HTTP/HTTPS/Dashboard fall back to Sōzune defaults — accurate for most
   *  setups but operators who override them in config.yaml will see wrong
   *  values until the API exposes them. */
  const listeners = $derived.by(() => {
    let apiPort = '3035';
    try {
      apiPort = new URL(getBaseUrl()).port || '3035';
    } catch {
      // ignore
    }
    return [
      { name: 'HTTP', port: `:80` },
      { name: 'HTTPS', port: `:443` },
      { name: 'API', port: `:${apiPort}` },
      { name: 'DASHBOARD', port: `:3038` }
    ];
  });

  const stats = $derived.by(() => {
    let backendsTotal = 0;
    let backendsDown = 0;
    const kinds = new Map<string, number>();
    let http = 0;
    let tcp = 0;
    let udp = 0;
    let tls = 0;
    for (const ep of entrypoints) {
      backendsTotal += ep.backends.length;
      const down = ep.unhealthy_backends ?? [];
      backendsDown += down.length;
      for (const u of down) {
        kinds.set(u.kind, (kinds.get(u.kind) ?? 0) + 1);
      }
      if (ep.protocol === 'Http') http += 1;
      else if (ep.protocol === 'Tcp') tcp += 1;
      else if (ep.protocol === 'Udp') udp += 1;
      if (ep.config.tls) tls += 1;
    }
    const totalEntrypoints = entrypoints.length;
    const backendsHealthy = backendsTotal - backendsDown;
    const healthyPct = backendsTotal === 0 ? 0 : Math.round((backendsHealthy / backendsTotal) * 100);

    return {
      total: totalEntrypoints,
      http,
      tcp,
      udp,
      tls,
      backendsTotal,
      backendsHealthy,
      backendsDown,
      healthyPct,
      kinds
    };
  });

  /** Compact "46 timeout · 1 connection_refused" summary of failure kinds. */
  const kindsLabel = $derived.by(() => {
    const parts: string[] = [];
    for (const [kind, count] of stats.kinds.entries()) {
      parts.push(`${count} ${kind.replaceAll('_', ' ')}`);
    }
    return parts.join(' · ') || '—';
  });

  const diagCounts = $derived.by(() => {
    let err = 0;
    let warn = 0;
    let info = 0;
    for (const d of globalDiagnostics) {
      if (d.severity === 'error') err += 1;
      else if (d.severity === 'warn') warn += 1;
      else if (d.severity === 'info') info += 1;
    }
    for (const ep of entrypoints) {
      for (const d of ep.diagnostics ?? []) {
        if (d.severity === 'error') err += 1;
        else if (d.severity === 'warn') warn += 1;
        else if (d.severity === 'info') info += 1;
      }
    }
    return { err, warn, info, total: err + warn + info };
  });

  /** Critical events table: backends currently down with their failure reason
   *  and how long they've been failing. Drawn from `unhealthy_backends[].since`,
   *  no historical store needed. Capped at 5 most recent. */
  type CritRow = {
    sev: 'CRITICAL' | 'WARN';
    when: string;
    sinceEpoch: number;
    source: string;
    detail: string;
    kind: string;
  };

  const criticalRows = $derived.by<CritRow[]>(() => {
    const rows: CritRow[] = [];
    const now = Math.floor(Date.now() / 1000);
    for (const ep of entrypoints) {
      for (const u of ep.unhealthy_backends ?? []) {
        const since = Number(u.since ?? 0);
        rows.push({
          sev: 'CRITICAL',
          when: relativeShort(now - since),
          sinceEpoch: since,
          source: ep.config.hostnames[0] ?? ep.name,
          detail: `${u.address} down · ${u.kind.replaceAll('_', ' ').toUpperCase()}`,
          kind: u.kind
        });
      }
    }
    // Most recent failures first (largest `since` = most recent).
    rows.sort((a, b) => b.sinceEpoch - a.sinceEpoch);
    return rows.slice(0, 5);
  });

  function relativeShort(secs: number): string {
    if (secs < 60) return `${secs}s`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m`;
    if (secs < 86400) {
      const h = Math.floor(secs / 3600);
      const m = Math.floor((secs % 3600) / 60);
      return m > 0 ? `${h}h ${m}m` : `${h}h`;
    }
    return `${Math.floor(secs / 86400)}d`;
  }

  function timeAgo(d: Date | null): string {
    if (!d) return '';
    const s = Math.floor((Date.now() - d.getTime()) / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    return `${Math.floor(s / 3600)}h ago`;
  }

  const enabledProviders = $derived(providers.filter((p) => p.configured));

  /** Banner state: error if anything is down or critical diag, warn for warns,
   *  otherwise ok. */
  const systemStatus = $derived.by<{ label: string; tone: 'ok' | 'warn' | 'err' }>(() => {
    if (stats.backendsDown > 0 || diagCounts.err > 0)
      return { label: 'degraded', tone: 'err' };
    if (diagCounts.warn > 0) return { label: 'warnings', tone: 'warn' };
    return { label: 'running', tone: 'ok' };
  });
</script>

<main class="overview">
  <header class="topbar">
    <div>
      <h1>Overview</h1>
      <div class="sub">
        All systems at a glance. {stats.total} routes serving traffic.
      </div>
    </div>
    <div class="topbar-right">
      <span class="status-pill status-{systemStatus.tone}">
        <span class="status-ind"></span> {systemStatus.label}
      </span>
      {#if lastRefresh}
        <span class="updated">updated {timeAgo(lastRefresh)}</span>
      {/if}
    </div>
  </header>

  {#if error}
    <div class="alert"><strong>error</strong> {error}</div>
  {/if}

  <section class="grid">
    <!-- Routes -->
    <article class="card">
      <div class="head">
        <span class="title">Routes</span>
        <span class="pill pill-ok"><span class="dot"></span> running</span>
      </div>
      <div class="value">{stats.total}<small>entrypoints</small></div>
      <div class="sub">
        {stats.http} HTTP &nbsp;·&nbsp; {stats.tcp} TCP &nbsp;·&nbsp; {stats.udp} UDP
      </div>
      <div class="foot">
        <span></span>
        <a class="link" href="./entrypoints">View all <span class="arr">→</span></a>
      </div>
    </article>

    <!-- Backends -->
    <article class="card">
      <div class="head">
        <span class="title">Backends</span>
        <span class="pill pill-{stats.backendsDown > 0 ? 'err' : 'ok'}">
          <span class="dot"></span>
          {stats.backendsDown > 0 ? `${stats.backendsDown} down` : 'all up'}
        </span>
      </div>
      <div class="value">
        <span class="value-ok">{stats.backendsHealthy}</span><small>/ {stats.backendsTotal} healthy</small>
      </div>
      <div class="sub">{kindsLabel}</div>
      <div class="foot">
        <span class="healthy-pct mono">{stats.healthyPct}%</span>
        <a class="link" href="./entrypoints">Inspect <span class="arr">→</span></a>
      </div>
    </article>

    <!-- Providers -->
    <article class="card">
      <div class="head">
        <span class="title">Providers</span>
        <span class="pill pill-ok">
          <span class="dot"></span>
          {enabledProviders.filter((p) => p.enabled).length} active
        </span>
      </div>
      <div class="value">
        {enabledProviders.filter((p) => p.enabled).length}<small>/ {providers.length} enabled</small>
      </div>
      <div class="prov-row">
        {#each providers as p}
          <span class="prov" class:on={p.enabled} class:off={!p.enabled}>
            {p.name}{p.enabled ? ` · ${p.entrypoint_count}` : ''}
          </span>
        {/each}
      </div>
      <div class="foot">
        <span></span>
        <a class="link" href="./providers">Manage <span class="arr">→</span></a>
      </div>
    </article>

    <!-- Diagnostics -->
    <article class="card">
      <div class="head">
        <span class="title">Diagnostics</span>
        <span
          class="pill pill-{diagCounts.err > 0 ? 'err' : diagCounts.warn > 0 ? 'warn' : 'ok'}"
        >
          <span class="dot"></span>
          {diagCounts.total > 0 ? `${diagCounts.total} active` : 'clean'}
        </span>
      </div>
      <div class="value">
        {diagCounts.total}<small>
          {#if diagCounts.err > 0}<span class="value-err">{diagCounts.err} err</span>{/if}
          {#if diagCounts.err > 0 && diagCounts.warn > 0}&nbsp;·&nbsp;{/if}
          {#if diagCounts.warn > 0}<span class="value-warn">{diagCounts.warn} warn</span>{/if}
          {#if diagCounts.total === 0}no issues detected{/if}
        </small>
      </div>
      <div class="sub">
        {#if diagCounts.total === 0}
          Label parser, route collisions and runtime checks all pass.
        {:else}
          Configuration issues raised by the label parser and runtime lints.
        {/if}
      </div>
      <div class="foot">
        <span></span>
        <a class="link" href="./diagnostics">Review <span class="arr">→</span></a>
      </div>
    </article>

    <!-- TLS -->
    <article class="card">
      <div class="head">
        <span class="title">TLS</span>
        <span class="pill pill-ok"><span class="dot"></span> {stats.tls} routes</span>
      </div>
      <div class="value">{stats.tls}<small>HTTPS entrypoints</small></div>
      <div class="sub">
        {stats.total - stats.tls} plain HTTP &nbsp;·&nbsp; certificate inventory coming
      </div>
      <div class="foot">
        <span></span>
        <a class="link" href="./certificates">Certificates <span class="arr">→</span></a>
      </div>
    </article>

    <!-- ACME (placeholder until /acme endpoint exposes status) -->
    <article class="card">
      <div class="head">
        <span class="title">ACME</span>
        <span class="pill pill-muted"><span class="dot"></span> see config</span>
      </div>
      <div class="value">—<small>status not exposed yet</small></div>
      <div class="sub">
        Let's Encrypt resolver state is configured in <code>acme.*</code>. A future API
        endpoint will surface live state here.
      </div>
      <div class="foot">
        <span></span>
        <a class="link" href="./settings">Settings <span class="arr">→</span></a>
      </div>
    </article>

    <!-- Listeners -->
    <article class="card">
      <div class="head">
        <span class="title">Listeners</span>
        <span class="pill pill-ok"><span class="dot"></span> {listeners.length} bound</span>
      </div>
      <div class="value">{listeners.length}<small>ports</small></div>
      <div class="lst">
        {#each listeners as l}
          <div class="lst-row"><b>{l.name}</b><span class="mono">{l.port}</span></div>
        {/each}
      </div>
      <div class="foot">
        <span></span>
        <a class="link" href="./health">Health <span class="arr">→</span></a>
      </div>
    </article>

    <!-- Critical summary -->
    <article class="card">
      <div class="head">
        <span class="title">Critical</span>
        <span class="pill pill-{criticalRows.length > 0 ? 'err' : 'ok'}">
          <span class="dot"></span>
          {criticalRows.length > 0 ? 'action req.' : 'all clear'}
        </span>
      </div>
      <div class="value">
        <span class={criticalRows.length > 0 ? 'value-err' : 'value-ok'}
          >{criticalRows.length}</span
        ><small>{criticalRows.length === 1 ? 'event' : 'events'}</small>
      </div>
      <div class="sub">
        {#if criticalRows.length > 0}
          See the events table below for details.
        {:else}
          No backends down, no critical diagnostics. Everything routing.
        {/if}
      </div>
      <div class="foot">
        <span></span>
        <a class="link" href="./diagnostics">Diagnostics <span class="arr">→</span></a>
      </div>
    </article>
  </section>

  {#if criticalRows.length > 0}
    <section class="section">
      <header class="section-head">
        <h2 class="section-title">Critical · recent events</h2>
        <span class="pill pill-err"
          ><span class="dot"></span> {criticalRows.length} active</span
        >
      </header>
      <table class="evt-table">
        <thead>
          <tr>
            <th>When</th>
            <th>Severity</th>
            <th>Source</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {#each criticalRows as row}
            <tr class="evt-row">
              <td class="t-when">{row.when}</td>
              <td><span class="sev-pill sev-pill-err">{row.sev}</span></td>
              <td class="t-src mono">{row.source}</td>
              <td class="t-det">{row.detail}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      <footer class="section-foot">
        <a class="link" style="color: var(--danger)" href="./diagnostics"
          >Open diagnostics <span class="arr">→</span></a
        >
      </footer>
    </section>
  {/if}
</main>

<style>
  .overview {
    padding: 24px 40px 32px;
    max-width: 1440px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .topbar {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    margin-bottom: 4px;
  }
  h1 {
    margin: 0;
    font-size: 22px;
    font-weight: 500;
    letter-spacing: -0.4px;
    color: var(--fg-0);
  }
  .sub {
    color: var(--fg-2);
    font-size: 13px;
    margin-top: 4px;
  }
  .topbar-right {
    display: flex;
    align-items: center;
    gap: 14px;
    font-size: 12px;
    color: var(--fg-2);
  }
  .updated {
    font-variant-numeric: tabular-nums;
  }

  .alert {
    background: var(--danger-bg);
    color: var(--danger);
    padding: 8px 14px;
    border-radius: var(--radius);
    font-size: 13px;
  }
  .alert strong {
    text-transform: uppercase;
    margin-right: 6px;
    font-size: 11px;
    letter-spacing: 0.08em;
  }

  /* Grid — 4 columns compact */
  .grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
  }

  .card {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px 16px;
    min-height: 132px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    transition: background 160ms ease, border-color 160ms ease;
  }
  .card:hover {
    background: var(--bg-2);
    border-color: var(--border-strong);
  }

  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .title {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1.6px;
    color: var(--fg-2);
    font-weight: 500;
  }

  .pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    color: var(--fg-3);
  }
  .pill .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--fg-3);
  }
  .pill-ok {
    color: var(--success);
  }
  .pill-ok .dot {
    background: var(--success);
    box-shadow: 0 0 6px rgba(63, 185, 80, 0.5);
  }
  .pill-warn {
    color: var(--warning);
  }
  .pill-warn .dot {
    background: var(--warning);
    box-shadow: 0 0 6px rgba(240, 180, 41, 0.5);
  }
  .pill-err {
    color: var(--danger);
  }
  .pill-err .dot {
    background: var(--danger);
    box-shadow: 0 0 6px rgba(248, 81, 73, 0.5);
  }
  .pill-muted {
    color: var(--fg-2);
  }

  .value {
    font-size: 34px;
    font-weight: 500;
    letter-spacing: -0.8px;
    line-height: 1;
    color: var(--fg-0);
    font-variant-numeric: tabular-nums;
    display: flex;
    align-items: baseline;
    gap: 8px;
  }
  .value small {
    font-size: 12px;
    color: var(--fg-2);
    font-weight: 400;
    letter-spacing: 0;
  }
  .value-ok {
    color: var(--success);
  }
  .value-warn {
    color: var(--warning);
  }
  .value-err {
    color: var(--danger);
  }

  .card .sub {
    font-size: 11.5px;
    color: var(--fg-2);
    line-height: 1.5;
    margin-top: 0;
  }

  .foot {
    margin-top: auto;
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    padding-top: 6px;
  }
  .healthy-pct {
    color: var(--fg-2);
    font-size: 13px;
  }
  .link {
    color: var(--fg-2);
    text-decoration: none;
    font-size: 12px;
  }
  .link:hover {
    color: var(--fg-0);
  }
  .link .arr {
    display: inline-block;
    transition: transform 120ms ease;
    margin-left: 4px;
  }
  .link:hover .arr {
    transform: translateX(3px);
    color: var(--accent);
  }

  /* Provider chips */
  .prov-row {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  .prov {
    font-size: 11px;
    padding: 3px 8px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.04);
    color: var(--fg-2);
    border: 1px solid var(--border);
  }
  .prov.on {
    color: var(--success);
    border-color: rgba(63, 185, 80, 0.25);
    background: rgba(63, 185, 80, 0.05);
  }
  .prov.off {
    color: var(--fg-3);
  }

  /* Listener list */
  .lst {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 12px;
    color: var(--fg-2);
  }
  .lst-row {
    display: flex;
    justify-content: space-between;
  }
  .lst-row b {
    color: var(--fg-0);
    font-weight: 500;
  }

  /* Free-flowing events section */
  .section {
    margin-top: 24px;
  }
  .section-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    margin-bottom: 14px;
  }
  .section-title {
    margin: 0;
    font-size: 12px;
    font-weight: 500;
    color: var(--fg-2);
    letter-spacing: 0.3px;
    text-transform: uppercase;
  }
  .section-foot {
    margin-top: 12px;
    display: flex;
    justify-content: flex-end;
  }

  .evt-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  .evt-table thead th {
    text-align: left;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    color: var(--fg-3);
    font-weight: 500;
    padding: 0 14px 8px;
    border-bottom: 1px solid var(--border-strong);
  }
  .evt-table thead th:first-child {
    padding-left: 0;
  }
  .evt-table thead th:last-child {
    padding-right: 0;
  }
  .evt-table tbody td {
    padding: 11px 14px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
    line-height: 1.45;
  }
  .evt-table tbody td:first-child {
    padding-left: 0;
  }
  .evt-table tbody td:last-child {
    padding-right: 0;
  }
  .evt-table tbody tr:last-child td {
    border-bottom: 0;
  }
  .evt-table tbody tr.evt-row:hover {
    background: rgba(255, 255, 255, 0.015);
  }
  .t-when {
    color: var(--fg-3);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
    width: 84px;
  }
  .t-src {
    color: var(--fg-0);
    font-size: 12.5px;
    width: 240px;
  }
  .t-det {
    color: var(--fg-2);
  }
  .sev-pill {
    display: inline-block;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    padding: 3px 8px;
    border-radius: 4px;
    white-space: nowrap;
  }
  .sev-pill-err {
    color: var(--danger);
    background: var(--danger-bg);
  }
  .sev-pill-warn {
    color: var(--warning);
    background: var(--warning-bg);
  }

  /* Status pill in top bar */
  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .status-pill .status-ind {
    width: 7px;
    height: 7px;
    border-radius: 50%;
  }
  .status-ok {
    color: var(--success);
    background: var(--success-bg);
  }
  .status-ok .status-ind {
    background: var(--success);
  }
  .status-warn {
    color: var(--warning);
    background: var(--warning-bg);
  }
  .status-warn .status-ind {
    background: var(--warning);
  }
  .status-err {
    color: var(--danger);
    background: var(--danger-bg);
  }
  .status-err .status-ind {
    background: var(--danger);
  }

  .mono {
    font-family: var(--font-mono);
  }
  code {
    font-family: var(--font-mono);
    font-size: 12px;
    background: rgba(255, 255, 255, 0.04);
    padding: 1px 5px;
    border-radius: 3px;
    color: var(--fg-0);
  }
</style>
