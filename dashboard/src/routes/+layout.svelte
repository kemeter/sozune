<script lang="ts">
  import '../app.css';
  import { page } from '$app/stores';
  import { onDestroy, onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { clearAuth, identity, isAuthenticated } from '$lib/auth';
  import { listDiagnostics } from '$lib/api';

  let { children } = $props();

  const nav = [
    { href: './', label: 'Entrypoints', icon: 'grid' },
    { href: './providers', label: 'Providers', icon: 'plug' },
    { href: './diagnostics', label: 'Diagnostics', icon: 'warning' },
    { href: './certificates', label: 'Certificates', icon: 'lock' },
    { href: './health', label: 'Health', icon: 'pulse' },
    { href: './settings', label: 'Settings', icon: 'gear' }
  ];

  /** Number of error+warn diagnostics; shown as a badge on the Diagnostics
   *  nav entry. Polled here so any page benefits from it without each page
   *  having to fetch it separately. */
  let diagBadge = $state(0);
  let diagPoll: ReturnType<typeof setInterval> | null = null;

  function isActive(href: string): boolean {
    const current = $page.url.pathname.replace(/\/$/, '');
    const target = href.replace(/^\.\//, '/').replace(/\/$/, '');
    if (target === '') return current === '';
    return current === target || current.startsWith(target + '/');
  }

  let onLoginPage = $derived($page.url.pathname.endsWith('/login'));

  async function refreshDiagBadge() {
    try {
      const r = await listDiagnostics();
      const all = [...(r.global ?? []), ...r.items.flatMap((i) => i.diagnostics)];
      diagBadge = all.filter((d) => d.severity === 'error' || d.severity === 'warn').length;
    } catch {
      diagBadge = 0;
    }
  }

  onMount(() => {
    if (!onLoginPage && !isAuthenticated()) {
      goto('./login');
      return;
    }
    if (!onLoginPage) {
      void refreshDiagBadge();
      diagPoll = setInterval(() => void refreshDiagBadge(), 5000);
    }
  });

  onDestroy(() => {
    if (diagPoll) clearInterval(diagPoll);
  });

  function logout() {
    clearAuth();
    goto('./login');
  }
</script>

{#if onLoginPage}
  {@render children()}
{:else}
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="logo">s</div>
        <div class="brand-text">
          <div class="brand-name">sozune</div>
          <div class="brand-sub">dashboard</div>
        </div>
      </div>

      <nav>
        {#each nav as item}
          <a href={item.href} class="nav-item" class:active={isActive(item.href)}>
            <span class="nav-icon" data-icon={item.icon}>
              {#if item.icon === 'grid'}
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/><rect x="2" y="9" width="5" height="5" rx="1"/><rect x="9" y="9" width="5" height="5" rx="1"/></svg>
              {:else if item.icon === 'lock'}
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="7" width="10" height="7" rx="1"/><path d="M5 7V4.5a3 3 0 0 1 6 0V7"/></svg>
              {:else if item.icon === 'pulse'}
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1 8h3l2-5 3 10 2-5h4"/></svg>
              {:else if item.icon === 'gear'}
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="2.5"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.05 3.05l1.4 1.4M11.55 11.55l1.4 1.4M3.05 12.95l1.4-1.4M11.55 4.45l1.4-1.4"/></svg>
              {:else if item.icon === 'warning'}
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 2L1.5 13.5h13L8 2z"/><path d="M8 6.5v3.5"/><circle cx="8" cy="11.5" r="0.5" fill="currentColor"/></svg>
              {:else if item.icon === 'plug'}
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 1v3M10 1v3"/><rect x="4" y="4" width="8" height="5" rx="1"/><path d="M8 9v3a2 2 0 0 0 2 2h2"/></svg>
              {/if}
            </span>
            <span>{item.label}</span>
            {#if item.label === 'Diagnostics' && diagBadge > 0}
              <span class="nav-badge">{diagBadge}</span>
            {/if}
          </a>
        {/each}
      </nav>

      <div class="sidebar-footer">
        {#if $identity}
          <div class="user">
            <div class="user-name">{$identity.name}</div>
            <div class="user-role">{$identity.role}</div>
          </div>
          <button class="logout" onclick={logout}>Sign out</button>
        {/if}
        <a class="doc-link" href="https://sozune.kemeter.io/documentation" target="_blank" rel="noopener noreferrer">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h4a2 2 0 0 1 2 2v9a2 2 0 0 0-2-2H2zM14 3h-4a2 2 0 0 0-2 2v9a2 2 0 0 1 2-2h4z"/></svg>
          <span>Documentation</span>
        </a>
        <div class="version mono">v0.11.0</div>
      </div>
    </aside>

    <main class="main">
      {@render children()}
    </main>
  </div>
{/if}

<style>
  .shell {
    display: grid;
    grid-template-columns: 220px 1fr;
    min-height: 100vh;
  }

  .sidebar {
    background: var(--bg-1);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    padding: 1rem 0.75rem;
    position: sticky;
    top: 0;
    height: 100vh;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.25rem 0.5rem 1.25rem;
    margin-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
  }

  .logo {
    width: 32px;
    height: 32px;
    border-radius: 8px;
    background: linear-gradient(135deg, var(--accent), #3a6fd9);
    color: white;
    display: grid;
    place-items: center;
    font-weight: 700;
    font-size: 1.05rem;
    box-shadow: 0 2px 8px rgba(91, 141, 255, 0.3);
  }

  .brand-name {
    font-weight: 600;
    font-size: 0.95rem;
    letter-spacing: -0.01em;
  }

  .brand-sub {
    font-size: 0.7rem;
    color: var(--fg-2);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  nav {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin-top: 0.5rem;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: 0.625rem;
    padding: 0.5rem 0.625rem;
    border-radius: var(--radius);
    color: var(--fg-1);
    font-size: 0.825rem;
    font-weight: 500;
    transition: background 0.1s, color 0.1s;
  }
  .nav-item:hover {
    background: var(--bg-hover);
    color: var(--fg-0);
  }
  .nav-item.active {
    background: var(--accent-bg);
    color: var(--accent);
  }

  .nav-icon {
    display: grid;
    place-items: center;
    width: 16px;
    height: 16px;
  }
  .nav-icon :global(svg) {
    width: 16px;
    height: 16px;
  }

  .nav-badge {
    margin-left: auto;
    background: var(--warning);
    color: #1a1a1a;
    font-size: 0.65rem;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 999px;
    line-height: 1.4;
    font-variant-numeric: tabular-nums;
  }

  .sidebar-footer {
    margin-top: auto;
    padding: 0.75rem 0.625rem 0.25rem;
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .user {
    display: flex;
    flex-direction: column;
  }

  .user-name {
    font-size: 0.8rem;
    font-weight: 500;
    color: var(--fg-0);
  }

  .user-role {
    font-size: 0.7rem;
    color: var(--fg-2);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .logout {
    background: var(--bg-2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--fg-1);
    font-size: 0.75rem;
    padding: 0.4rem 0.625rem;
    text-align: left;
  }
  .logout:hover {
    background: var(--bg-hover);
    color: var(--fg-0);
  }

  .doc-link {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.4rem 0.625rem;
    border-radius: var(--radius);
    color: var(--fg-2);
    font-size: 0.75rem;
    font-weight: 500;
  }
  .doc-link:hover {
    background: var(--bg-hover);
    color: var(--fg-0);
  }
  .doc-link :global(svg) {
    width: 14px;
    height: 14px;
  }

  .version {
    color: var(--fg-3);
    font-size: 0.7rem;
  }

  .main {
    padding: 2rem 2.5rem;
    max-width: 1400px;
    width: 100%;
  }
</style>
