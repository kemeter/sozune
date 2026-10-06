<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { resolveRoute, type Resolution } from '$lib/api';
  import { isAuthenticated } from '$lib/auth';

  const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'];

  /** Read a query param with a default. Safe before mount (SSR returns the
   *  fallback). */
  function getParam(key: string, fallback: string): string {
    if (typeof window === 'undefined') return fallback;
    return new URL(window.location.href).searchParams.get(key) ?? fallback;
  }

  // The request lives in the URL so a test can be shared, reloaded, or opened
  // pre-filled from an entrypoint's page. Headers never do: they can carry
  // credentials, which would end up in the history and in shared links.
  let url = $state(getParam('url', ''));
  let method = $state(getParam('method', 'GET'));
  /** One `Name: value` per line. */
  let headers = $state('');
  let clientIp = $state(getParam('client_ip', ''));

  type Submitted = { url: string; method: string; headers: string; clientIp: string };
  let result = $state<Resolution | null>(null);
  /** The request `result` answers: the URL is synced from it, and the result
   *  is marked stale once the form no longer matches it. */
  let submitted = $state<Submitted | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(false);

  function parseHeaders(raw: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      const i = line.indexOf(':');
      if (i <= 0) {
        throw new Error(`header "${line.trim()}" is not "Name: value"`);
      }
      out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    return out;
  }

  /** The API answers errors as `{"error": "..."}`; show that, not the raw body. */
  function readError(e: unknown): string {
    const message = e instanceof Error ? e.message : String(e);
    const body = message.indexOf('{');
    if (body >= 0) {
      try {
        const parsed = JSON.parse(message.slice(body));
        if (typeof parsed.error === 'string') return parsed.error;
      } catch {
        // not JSON: fall through to the raw message
      }
    }
    return message;
  }

  function syncUrl(request: Submitted) {
    const params = new URLSearchParams();
    if (request.url) params.set('url', request.url);
    if (request.method !== 'GET') params.set('method', request.method);
    if (request.clientIp) params.set('client_ip', request.clientIp);
    // The headers are not in the URL: reloaded or shared, this test would run
    // without them and could answer differently. Leave it to be completed.
    if (request.headers.trim()) params.set('run', '0');
    const query = params.toString();
    void goto(`${window.location.pathname}${query ? `?${query}` : ''}`, {
      replaceState: true,
      keepFocus: true,
      noScroll: true
    });
  }

  async function run() {
    if (!url.trim()) return;
    // Snapshot taken before the await: edits made while it is in flight belong
    // to the next request, not to this answer.
    const request: Submitted = { url: url.trim(), method, headers, clientIp: clientIp.trim() };
    loading = true;
    error = null;
    try {
      result = await resolveRoute({
        url: request.url,
        method: request.method,
        headers: parseHeaders(request.headers),
        client_ip: request.clientIp || undefined
      });
      submitted = request;
      syncUrl(request);
    } catch (e) {
      result = null;
      error = readError(e);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    if (!isAuthenticated()) {
      goto('./login');
      return;
    }
    // `run=0`: pre-filled but left to complete, e.g. a regex path that no
    // URL can be derived from.
    if (url && getParam('run', '1') !== '0') void run();
  });

  const served = $derived(
    result !== null &&
      (result.outcome === 'proxied' ||
        result.outcome === 'redirected' ||
        result.outcome === 'acme_challenge')
  );

  /** A route serves the request, but none of its backends passes its health
   *  check: it will not get an answer from one. */
  const degraded = $derived(
    served &&
      result !== null &&
      result.backends.length > 0 &&
      result.backends.every((b) => !b.healthy)
  );

  const stale = $derived(
    submitted !== null &&
      (submitted.url !== url.trim() ||
        submitted.method !== method ||
        submitted.headers !== headers ||
        submitted.clientIp !== clientIp.trim())
  );

  const stepGlyph: Record<string, string> = {
    pass: '✓',
    blocked: '✗',
    applies: '•',
    not_evaluated: '?'
  };
</script>

<header class="page-header">
  <div>
    <h1>Route tester</h1>
    <p class="subtitle">
      Which route serves a request, and why the others do not. Nothing is sent to a backend.
    </p>
  </div>
</header>

<form
  class="form"
  onsubmit={(e) => {
    e.preventDefault();
    void run();
  }}
>
  <div class="row">
    <select class="method mono" bind:value={method} aria-label="Method">
      {#each METHODS as m}
        <option value={m}>{m}</option>
      {/each}
    </select>
    <input
      class="url mono"
      type="text"
      placeholder="https://app.example.com/api/users"
      bind:value={url}
      aria-label="URL"
    />
    <button class="btn-primary" type="submit" disabled={loading || !url.trim()}>
      {loading ? 'resolving…' : 'Resolve'}
    </button>
  </div>
  <div class="row extra">
    <label class="field">
      <span class="field-label">Headers <span class="hint">one per line, Name: value</span></span>
      <textarea class="mono" rows="2" placeholder="X-Tenant: acme" bind:value={headers}></textarea>
    </label>
    <label class="field client">
      <span class="field-label">Client IP <span class="hint">for IP-based rules</span></span>
      <input class="mono" type="text" placeholder="203.0.113.7" bind:value={clientIp} />
    </label>
  </div>
</form>

{#if error}
  <div class="alert">
    <strong>error</strong> {error}
  </div>
{/if}

{#if result}
  {#if stale}
    <div class="stale-note">the request changed since this result: Resolve again</div>
  {/if}
  <div class="result" class:stale>
  <section class="verdict" class:ok={served && !degraded} class:warn={degraded} class:ko={!served}>
    <div class="verdict-head">
      <span class="verdict-glyph">{degraded ? '⚠' : served ? '✓' : '✗'}</span>
      <span class="verdict-summary">{result.summary}</span>
      {#if result.status !== null}
        <span class="status mono">{result.status}</span>
      {/if}
    </div>
    {#if result.route}
      <div class="verdict-route">
        route
        <a class="mono" href={`/entrypoints/${encodeURIComponent(result.route.id)}`}>{result.route.id}</a>
        · {result.route.source ?? 'unknown source'} · priority {result.route.priority}
      </div>
    {/if}
  </section>

  {#if result.candidates.length > 0}
    <section class="group">
      <h2 class="group-title">Other routes on this host</h2>
      <div class="list">
        {#each result.candidates as c}
          <div class="item item-{c.verdict}">
            <div class="item-head">
              <a class="mono" href={`/entrypoints/${encodeURIComponent(c.id)}`}>{c.name}</a>
              <span class="chip">priority {c.priority}</span>
              <span class="chip chip-{c.verdict}">{c.verdict}</span>
            </div>
            <div class="item-detail">{c.reason}</div>
          </div>
        {/each}
      </div>
    </section>
  {/if}

  {#if result.pipeline.length > 0}
    <section class="group">
      <h2 class="group-title">Middlewares, in order</h2>
      <div class="list">
        {#each result.pipeline as s}
          <div class="item step-{s.verdict}">
            <div class="item-head">
              <span class="glyph">{stepGlyph[s.verdict]}</span>
              <span class="mono">{s.name}</span>
              <span class="chip">{s.verdict.replace('_', ' ')}</span>
            </div>
            {#if s.detail}
              <div class="item-detail">{s.detail}</div>
            {/if}
          </div>
        {/each}
      </div>
    </section>
  {/if}

  {#if result.backends.length > 0}
    <section class="group">
      <h2 class="group-title">Backends</h2>
      <div class="list">
        {#each result.backends as b}
          <div class="item" class:step-pass={b.healthy} class:step-blocked={!b.healthy}>
            <div class="item-head">
              <span class="glyph">{b.healthy ? '✓' : '✗'}</span>
              <span class="mono">{b.address}</span>
            </div>
            {#if b.reason}
              <div class="item-detail">{b.reason}</div>
            {/if}
          </div>
        {/each}
      </div>
    </section>
  {/if}
  </div>
{:else if !error && !loading}
  <div class="empty">
    {url
      ? 'complete the request (path, headers this route matches on), then Resolve'
      : 'enter a URL to see which route serves it'}
  </div>
{/if}

<style>
  .page-header {
    margin-bottom: 1.5rem;
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

  .form {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1rem;
    margin-bottom: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .row {
    display: flex;
    gap: 0.5rem;
    align-items: stretch;
  }
  .method {
    width: 7rem;
  }
  .url {
    flex: 1;
    min-width: 0;
  }
  .extra {
    flex-wrap: wrap;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    flex: 2;
    min-width: 220px;
  }
  .field.client {
    flex: 1;
  }
  .field-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--fg-2);
    font-weight: 500;
  }
  .hint {
    text-transform: none;
    letter-spacing: 0;
    color: var(--fg-3);
    font-weight: 400;
  }
  textarea {
    resize: vertical;
    background: var(--bg-2);
    color: var(--fg-0);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.5rem 0.65rem;
    font-size: 0.8rem;
  }
  .btn-primary {
    border: 1px solid var(--accent);
    border-radius: var(--radius);
    padding: 0.5rem 1rem;
    font-size: 0.8rem;
    font-weight: 500;
    background: var(--accent);
    color: #fff;
  }
  .btn-primary:hover {
    background: var(--accent-hover);
  }
  .btn-primary:disabled {
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

  .result.stale {
    opacity: 0.45;
  }
  .stale-note {
    color: var(--warning);
    font-size: 0.78rem;
    margin-bottom: 0.6rem;
  }
  .verdict {
    border: 1px solid var(--border);
    border-left-width: 3px;
    border-radius: var(--radius-lg);
    padding: 0.875rem 1rem;
    background: var(--bg-1);
    margin-bottom: 1.5rem;
  }
  .verdict.ok {
    border-left-color: var(--success);
  }
  .verdict.ko {
    border-left-color: var(--danger);
  }
  .verdict.warn {
    border-left-color: var(--warning);
  }
  .warn .verdict-glyph {
    color: var(--warning);
  }
  .verdict-head {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-size: 0.95rem;
  }
  .verdict-glyph {
    font-size: 1.1rem;
  }
  .ok .verdict-glyph {
    color: var(--success);
  }
  .ko .verdict-glyph {
    color: var(--danger);
  }
  .verdict-summary {
    flex: 1;
    color: var(--fg-0);
  }
  .status {
    background: var(--danger-bg);
    color: var(--danger);
    padding: 1px 8px;
    border-radius: 3px;
    font-size: 0.75rem;
    font-weight: 600;
  }
  .verdict-route {
    margin-top: 0.4rem;
    margin-left: 1.7rem;
    color: var(--fg-2);
    font-size: 0.78rem;
  }

  .group {
    margin-bottom: 1.5rem;
  }
  .group-title {
    font-size: 0.825rem;
    font-weight: 500;
    color: var(--fg-2);
    margin: 0 0 0.5rem;
  }
  .list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .item {
    border: 1px solid var(--border);
    border-left-width: 3px;
    border-radius: var(--radius);
    padding: 0.55rem 0.875rem;
    background: var(--bg-1);
  }
  .item-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.825rem;
    color: var(--fg-0);
  }
  .item-detail {
    color: var(--fg-2);
    font-size: 0.78rem;
    margin-top: 0.3rem;
  }
  .glyph {
    width: 1rem;
    text-align: center;
  }
  .chip {
    background: var(--bg-3);
    color: var(--fg-2);
    font-size: 0.7rem;
    padding: 1px 7px;
    border-radius: 999px;
  }
  .item-shadowed,
  .step-applies {
    border-left-color: var(--accent);
  }
  .item-rejected,
  .step-not_evaluated {
    border-left-color: var(--border-strong);
  }
  .item-refused,
  .step-blocked {
    border-left-color: var(--danger);
  }
  .step-pass {
    border-left-color: var(--success);
  }
  .chip-refused {
    background: var(--danger-bg);
    color: var(--danger);
  }
  .chip-shadowed {
    background: var(--accent-bg);
    color: var(--accent);
  }
  .step-blocked .glyph {
    color: var(--danger);
  }
  .step-pass .glyph {
    color: var(--success);
  }
</style>
