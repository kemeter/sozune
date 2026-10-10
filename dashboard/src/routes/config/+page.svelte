<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { getConfig, type ConfigView } from '$lib/api';
  import { isAuthenticated } from '$lib/auth';

  let config = $state<ConfigView | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(true);

  /** A resolver as `/config` describes it: tagged by its challenge. */
  type Resolver = {
    challenge: 'http-01' | 'dns-01' | 'tls-alpn-01';
    provider?: string;
    required_env?: string[];
    domains?: string[];
    ca_server?: string | null;
  };

  const resolvers = $derived(
    Object.entries((config?.acme?.resolvers ?? {}) as Record<string, Resolver>).sort(([a], [b]) =>
      a.localeCompare(b)
    )
  );

  /** Providers in a fixed order, enabled first, each with the details
   *  `/config` gives for it. */
  const providers = $derived.by(() => {
    if (!config) return [];
    const p = config.providers;
    const rows: { name: string; enabled: boolean; details: [string, string][] }[] = [];
    const docker = (name: string, v: typeof p.docker) => {
      if (!v) return;
      rows.push({
        name,
        enabled: v.enabled,
        details: [
          ['endpoint', v.endpoint],
          ['expose by default', v.expose_by_default ? 'yes' : 'no']
        ]
      });
    };
    docker('Docker', p.docker);
    docker('Podman', p.podman);
    docker('Swarm', p.swarm);
    for (const [name, v] of [
      ['Kubernetes', p.kubernetes],
      ['Nomad', p.nomad],
      ['Consul', p.consul],
      ['Ring', p.ring]
    ] as const) {
      if (v) rows.push({ name, enabled: v.enabled, details: [] });
    }
    if (p.config_file) {
      rows.push({
        name: 'Config file',
        enabled: p.config_file.enabled,
        details: [
          ['path', p.config_file.path],
          ['watch', p.config_file.watch ? 'yes' : 'no']
        ]
      });
    }
    if (p.http) {
      rows.push({
        name: 'HTTP',
        enabled: p.http.enabled,
        details: [
          ['url', p.http.url],
          ['poll interval', `${p.http.poll_interval}s`]
        ]
      });
    }
    return rows.sort((a, b) => Number(b.enabled) - Number(a.enabled));
  });

  const streamListeners = $derived(
    config
      ? [
          ...config.listeners.tcp.map((l) => ({ ...l, protocol: 'tcp' as const })),
          ...config.listeners.udp.map((l) => ({ ...l, protocol: 'udp' as const }))
        ]
      : []
  );

  async function load() {
    loading = true;
    try {
      config = await getConfig();
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
  });
</script>

<header class="page-header">
  <div>
    <h1>Config</h1>
    <p class="subtitle">
      The configuration the running instance loaded, environment overrides included. Read-only,
      secrets masked.
    </p>
  </div>
  <div class="header-actions">
    {#if config}
      <span class="refresh-meta mono">v{config.version}</span>
    {/if}
    <button class="btn-secondary" onclick={() => load()} disabled={loading}>
      {loading ? 'loading…' : 'Refresh'}
    </button>
  </div>
</header>

{#if error}
  <div class="alert"><strong>error</strong> {error}</div>
{/if}

{#if config}
  <div class="grid">
    <section class="card">
      <h2>Listeners</h2>
      <dl>
        <dt>HTTP</dt>
        <dd class="mono">:{config.listeners.http.port}</dd>
        <dt>HTTPS</dt>
        <dd class="mono">:{config.listeners.https.port}</dd>
        <dt>client idle</dt>
        <dd class="mono">{config.listeners.timeouts.client_idle}s</dd>
        <dt>backend idle</dt>
        <dd class="mono">{config.listeners.timeouts.backend_idle}s</dd>
        <dt>backend connect</dt>
        <dd class="mono">{config.listeners.timeouts.backend_connect}s</dd>
        <dt>request</dt>
        <dd class="mono">{config.listeners.timeouts.request}s</dd>
      </dl>
    </section>

    <section class="card">
      <h2>API</h2>
      <dl>
        <dt>enabled</dt>
        <dd>{config.api.enabled ? 'yes' : 'no'}</dd>
        <dt>listen</dt>
        <dd class="mono">{config.api.listen_address}</dd>
        <dt>CORS origins</dt>
        <dd class="mono">
          {config.api.cors_origins.length > 0 ? config.api.cors_origins.join(', ') : 'any'}
        </dd>
      </dl>
    </section>

    <section class="card">
      <h2>Dashboard</h2>
      <dl>
        <dt>enabled</dt>
        <dd>{config.dashboard.enabled ? 'yes' : 'no'}</dd>
        <dt>listen</dt>
        <dd class="mono">{config.dashboard.listen_address}</dd>
      </dl>
    </section>

    {#if streamListeners.length > 0}
      <section class="card wide">
        <h2>TCP / UDP listeners</h2>
        <div class="rows">
          {#each streamListeners as l}
            <div class="row">
              <div class="row-head">
                <span class="mono">{l.name}</span>
                <span class="chip">{l.protocol}</span>
                <span class="mono">:{l.port}</span>
              </div>
              {#if 'ip_allow_list' in l}
                {#if l.ip_allow_list.length > 0}
                  <div class="row-detail">
                    allows <span class="mono">{l.ip_allow_list.join(', ')}</span>
                  </div>
                {/if}
                {#if l.rate_limit}
                  <div class="row-detail">
                    rate limit
                    <span class="mono">{l.rate_limit.max_conns} conns / {l.rate_limit.per_seconds}s</span>
                  </div>
                  {#if l.rate_limit.exempt.length > 0}
                    <div class="row-detail">
                      exempt from the limit
                      <span class="mono">{l.rate_limit.exempt.join(', ')}</span>
                    </div>
                  {/if}
                {/if}
                {#if l.idle_timeout !== null}
                  <div class="row-detail">idle timeout <span class="mono">{l.idle_timeout}s</span></div>
                {/if}
              {/if}
            </div>
          {/each}
        </div>
      </section>
    {/if}

    <section class="card wide">
      <h2>TLS</h2>
      <dl>
        <dt>min version</dt>
        <dd class="mono">{config.tls.min_version ?? 'default'}</dd>
        <dt>max version</dt>
        <dd class="mono">{config.tls.max_version ?? 'default'}</dd>
        <dt>ciphers</dt>
        <dd class="mono">{config.tls.ciphers ? config.tls.ciphers.join(', ') : 'default'}</dd>
        <dt>certificate files</dt>
        <dd class="mono">
          {config.tls.certificates.length > 0 ? config.tls.certificates.join(', ') : 'none'}
        </dd>
        <dt>client certificates</dt>
        <dd class="mono">{config.tls.client_auth ? config.tls.client_auth.mode : 'none'}</dd>
        {#if config.tls.client_auth && config.tls.client_auth.ca_files.length > 0}
          <dt>client CAs</dt>
          <dd class="mono">{config.tls.client_auth.ca_files.join(', ')}</dd>
        {/if}
        {#if config.tls.client_auth && config.tls.client_auth.crl_files.length > 0}
          <dt>client CRLs</dt>
          <dd class="mono">{config.tls.client_auth.crl_files.join(', ')}</dd>
        {/if}
      </dl>
    </section>

    <section class="card wide">
      <h2>ACME</h2>
      {#if config.acme?.enabled}
        <dl>
          <dt>email</dt>
          <dd class="mono">{config.acme.email}</dd>
          <dt>directory</dt>
          <dd>{config.acme.staging ? 'staging' : 'production'}</dd>
          <dt>HTTP-01 port</dt>
          <dd class="mono">:{config.acme.challenge_port}</dd>
        </dl>
        {#if resolvers.length > 0}
          <h3>Resolvers</h3>
          <div class="rows">
            {#each resolvers as [name, r]}
              <div class="row">
                <div class="row-head">
                  <span class="mono">{name}</span>
                  <span class="chip">{r.challenge}</span>
                  {#if r.provider}<span class="chip">{r.provider}</span>{/if}
                </div>
                {#if r.domains && r.domains.length > 0}
                  <div class="row-detail">domains <span class="mono">{r.domains.join(', ')}</span></div>
                {/if}
                {#if r.required_env && r.required_env.length > 0}
                  <div class="row-detail">reads <span class="mono">{r.required_env.join(', ')}</span></div>
                {/if}
                {#if r.ca_server}
                  <div class="row-detail">CA <span class="mono">{r.ca_server}</span></div>
                {/if}
              </div>
            {/each}
          </div>
        {/if}
      {:else}
        <p class="muted">disabled</p>
      {/if}
    </section>

    <section class="card wide">
      <h2>Providers</h2>
      <div class="rows">
        {#each providers as p}
          <div class="row" class:off={!p.enabled}>
            <div class="row-head">
              <span class="dot" class:on={p.enabled}></span>
              <span>{p.name}</span>
              <span class="chip">{p.enabled ? 'enabled' : 'disabled'}</span>
            </div>
            {#if p.enabled}
              {#each p.details as [key, value]}
                <div class="row-detail">{key} <span class="mono">{value}</span></div>
              {/each}
            {/if}
          </div>
        {/each}
      </div>
    </section>
  </div>
{:else if loading}
  <div class="empty">loading…</div>
{/if}

<style>
  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    margin-bottom: 1.75rem;
    gap: 1rem;
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

  .grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 1rem;
  }
  .card {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.1rem 1.25rem;
  }
  .card.wide {
    grid-column: 1 / -1;
  }
  h2 {
    margin: 0 0 0.9rem;
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--fg-1);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  h3 {
    margin: 1.1rem 0 0.5rem;
    font-size: 0.72rem;
    font-weight: 500;
    color: var(--fg-2);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.45rem 1rem;
    margin: 0;
    font-size: 0.82rem;
  }
  dt {
    color: var(--fg-2);
  }
  dd {
    margin: 0;
    color: var(--fg-0);
    word-break: break-all;
  }
  .muted {
    margin: 0;
    color: var(--fg-3);
    font-size: 0.82rem;
  }
  .rows {
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
  }
  .row {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.5rem 0.75rem;
    background: var(--bg-2);
  }
  .row.off {
    opacity: 0.55;
  }
  .row-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.82rem;
    color: var(--fg-0);
  }
  .row-detail {
    margin-top: 0.25rem;
    color: var(--fg-2);
    font-size: 0.76rem;
  }
  .chip {
    background: var(--bg-3);
    color: var(--fg-2);
    font-size: 0.7rem;
    padding: 1px 7px;
    border-radius: 999px;
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--fg-3);
  }
  .dot.on {
    background: var(--success);
  }

  @media (max-width: 900px) {
    .grid {
      grid-template-columns: 1fr;
    }
  }
</style>
