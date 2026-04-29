<script lang="ts">
  import { onMount } from 'svelte';
  import { getBaseUrl, setBaseUrl, health } from '$lib/api';

  let baseUrl = $state('');
  let saved = $state(false);
  let testStatus = $state<'idle' | 'pending' | 'ok' | 'fail'>('idle');
  let testMessage = $state('');

  onMount(() => {
    baseUrl = getBaseUrl();
  });

  function save() {
    setBaseUrl(baseUrl);
    saved = true;
    setTimeout(() => (saved = false), 2000);
  }

  async function testConnection() {
    testStatus = 'pending';
    testMessage = '';
    try {
      setBaseUrl(baseUrl);
      await health();
      testStatus = 'ok';
      testMessage = 'API reachable';
    } catch (e) {
      testStatus = 'fail';
      testMessage = e instanceof Error ? e.message : String(e);
    }
  }
</script>

<header class="page-header">
  <div>
    <h1>Settings</h1>
    <p class="subtitle">Connection to the sozune admin API</p>
  </div>
</header>

<section class="card">
  <h2>Connection</h2>

  <div class="field">
    <label for="baseUrl">API base URL</label>
    <input
      id="baseUrl"
      type="text"
      class="mono"
      placeholder="http://127.0.0.1:3035"
      bind:value={baseUrl}
    />
    <p class="hint">The host:port where the sozune API server listens.</p>
  </div>

  <p class="hint">
    Credentials are entered on the <a href="./login">sign-in page</a> and stored in this browser
    tab only.
  </p>

  <div class="actions">
    <button class="btn-primary" onclick={save}>
      {saved ? 'Saved ✓' : 'Save'}
    </button>
    <button class="btn-secondary" onclick={testConnection} disabled={testStatus === 'pending'}>
      {testStatus === 'pending' ? 'testing…' : 'Test connection'}
    </button>
    {#if testStatus === 'ok'}
      <span class="status ok">✓ {testMessage}</span>
    {:else if testStatus === 'fail'}
      <span class="status fail">✗ {testMessage}</span>
    {/if}
  </div>
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

  .card {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.5rem 1.75rem;
    max-width: 640px;
  }
  h2 {
    margin: 0 0 1.25rem;
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--fg-1);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .field {
    margin-bottom: 1.25rem;
  }
  label {
    display: block;
    font-size: 0.78rem;
    color: var(--fg-1);
    margin-bottom: 0.4rem;
    font-weight: 500;
  }
  input {
    width: 100%;
    padding: 0.55rem 0.75rem;
    background: var(--bg-2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--fg-0);
    outline: none;
    transition: border-color 0.1s;
  }
  input:focus {
    border-color: var(--accent);
  }
  input::placeholder {
    color: var(--fg-3);
  }
  .hint {
    margin: 0.35rem 0 0;
    font-size: 0.72rem;
    color: var(--fg-3);
  }
  .hint a {
    color: var(--accent);
  }

  .actions {
    display: flex;
    gap: 0.625rem;
    align-items: center;
    margin-top: 1.5rem;
    padding-top: 1.25rem;
    border-top: 1px solid var(--border);
  }
  .btn-primary,
  .btn-secondary {
    border: 1px solid transparent;
    border-radius: var(--radius);
    padding: 0.5rem 1rem;
    font-size: 0.8rem;
    font-weight: 500;
  }
  .btn-primary {
    background: var(--accent);
    color: white;
  }
  .btn-primary:hover {
    background: var(--accent-hover);
  }
  .btn-secondary {
    background: var(--bg-2);
    color: var(--fg-1);
    border-color: var(--border);
  }
  .btn-secondary:hover {
    background: var(--bg-hover);
    color: var(--fg-0);
  }
  .btn-secondary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .status {
    font-size: 0.78rem;
    font-weight: 500;
  }
  .status.ok {
    color: var(--success);
  }
  .status.fail {
    color: var(--danger);
  }
</style>
