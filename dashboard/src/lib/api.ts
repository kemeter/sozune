import { clearAuth, getCredentials } from './auth';

const BASE_URL_KEY = 'sozune.baseUrl';
const DEFAULT_BASE_URL = 'http://127.0.0.1:3035';

export function getBaseUrl(): string {
  if (typeof localStorage === 'undefined') {
    return DEFAULT_BASE_URL;
  }
  return localStorage.getItem(BASE_URL_KEY) ?? DEFAULT_BASE_URL;
}

export function setBaseUrl(url: string): void {
  if (typeof localStorage === 'undefined') {
    return;
  }
  localStorage.setItem(BASE_URL_KEY, url);
}

function basicHeader(name: string, password: string): string {
  return `Basic ${btoa(`${name}:${password}`)}`;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const credentials = getCredentials();
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (credentials) {
    headers.set('Authorization', basicHeader(credentials.name, credentials.password));
  }

  const res = await fetch(`${getBaseUrl()}${path}`, { ...init, headers });

  if (res.status === 401) {
    clearAuth();
    if (typeof window !== 'undefined' && !window.location.pathname.endsWith('/login')) {
      window.location.assign('./login');
    }
    throw new Error('401 Unauthorized');
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${res.status} ${res.statusText}${text ? `: ${text}` : ''}`);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

/** Validate a credential pair against `/me`. Used by the login page only —
 *  callers elsewhere should rely on the persisted credentials. */
export async function validateCredentials(
  baseUrl: string,
  name: string,
  password: string
): Promise<{ name: string; role: 'admin' | 'read-only' }> {
  const res = await fetch(`${baseUrl}/me`, {
    headers: {
      Accept: 'application/json',
      Authorization: basicHeader(name, password)
    }
  });
  if (res.status === 401) {
    throw new Error('Invalid credentials');
  }
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  return (await res.json()) as { name: string; role: 'admin' | 'read-only' };
}

export type Protocol = 'Http' | 'Tcp' | 'Udp';

export interface EntrypointConfig {
  hostnames: string[];
  tls: boolean;
  strip_prefix: boolean;
  https_redirect?: boolean;
  priority: number;
  sticky_session?: boolean;
  compress?: boolean;
  headers?: Record<string, string>;
  backend_timeout?: number | null;
  ip_allow_list?: string[];
  [key: string]: unknown;
}

export interface Backend {
  address: string;
  port: number;
  weight: number;
}

/** Backend identifier as used in `UnhealthyBackend.address`: `host:port`. */
export function backendKey(b: Backend): string {
  return `${b.address}:${b.port}`;
}

export type Severity = 'error' | 'warn' | 'info';

export interface Diagnostic {
  code: string;
  severity: Severity;
  message: string;
  label?: string;
  value?: string;
  hint?: string;
}

/** Classification of a failed health check. Matches `UnhealthyKind` server-side. */
export type UnhealthyKind =
  | 'connection_refused'
  | 'no_route_to_host'
  | 'network_unreachable'
  | 'host_unreachable'
  | 'timeout'
  | 'dns_failure'
  | 'bad_status'
  | 'http_error'
  | 'other';

export interface UnhealthyBackend {
  /** `host:port` of the backend that's failing health checks. */
  address: string;
  /** Coarse classification of the failure. */
  kind: UnhealthyKind;
  /** Raw error message from the last probe attempt. */
  message: string;
  /** Unix epoch (seconds) the backend was first marked down. */
  since: number;
  /** Unix epoch (seconds) of the last probe attempt. */
  last_checked: number;
}

export interface Entrypoint {
  id: string;
  name: string;
  protocol: Protocol;
  backends: Backend[];
  config: EntrypointConfig;
  source?: string | null;
  /** Backends currently marked down by the health checker, with failure reason. */
  unhealthy_backends?: UnhealthyBackend[];
  /** Diagnostics produced for this entrypoint by the label parser. */
  diagnostics?: Diagnostic[];
}

export interface DiagnosticsResponse {
  total: number;
  /** Diagnostics not attached to any single candidate (e.g. ACME-without-TLS). */
  global: Diagnostic[];
  items: { candidate_id: string; diagnostics: Diagnostic[] }[];
}

export interface Provider {
  /** Provider identifier — matches `entrypoint.source` for entries it emits. */
  name: string;
  /** The provider block exists in `config.yaml` (regardless of `enabled`). */
  configured: boolean;
  /** The provider is configured *and* its `enabled` flag is true. */
  enabled: boolean;
  /** Live count of entrypoints in storage whose `source` matches this provider. */
  entrypoint_count: number;
}

export interface ProvidersResponse {
  providers: Provider[];
}

export function listEntrypoints(): Promise<Entrypoint[]> {
  return request<Entrypoint[]>('/entrypoints');
}

export function listDiagnostics(): Promise<DiagnosticsResponse> {
  return request<DiagnosticsResponse>('/diagnostics');
}

export function listProviders(): Promise<ProvidersResponse> {
  return request<ProvidersResponse>('/providers');
}

export function getEntrypoint(id: string): Promise<Entrypoint> {
  return request<Entrypoint>(`/entrypoints/${encodeURIComponent(id)}`);
}

export function health(): Promise<unknown> {
  return request<unknown>('/health');
}

/** Read-only snapshot of the running config (auth-protected, admin only).
 *  Mirrors `ConfigView` on the server: listener ports, ACME, providers,
 *  dashboard listener, API listener. No user list. */
export interface ConfigView {
  version: string;
  listeners: { http: { port: number }; https: { port: number } };
  acme: {
    enabled: boolean;
    email: string;
    staging: boolean;
    challenge_port: number;
    resolvers: Record<string, unknown>;
  } | null;
  providers: {
    docker?: { enabled: boolean; endpoint: string; expose_by_default: boolean } | null;
    podman?: { enabled: boolean; endpoint: string; expose_by_default: boolean } | null;
    swarm?: { enabled: boolean; endpoint: string; expose_by_default: boolean } | null;
    kubernetes?: { enabled: boolean } | null;
    nomad?: { enabled: boolean } | null;
    consul?: { enabled: boolean } | null;
    config_file?: { enabled: boolean; path: string; watch: boolean } | null;
    http?: { enabled: boolean; url: string; poll_interval: number } | null;
  };
  dashboard: { enabled: boolean; listen_address: string };
  api: { enabled: boolean; listen_address: string; cors_origins: string[] };
}

export function getConfig(): Promise<ConfigView> {
  return request<ConfigView>('/config');
}

/** JSON view of the `/metrics` endpoint. Same numbers as the Prometheus
 *  text exposition, in a shape the dashboard can read directly without
 *  hand-rolling a parser. */
export interface MetricsView {
  static: {
    entrypoints: number;
    entrypoints_by_protocol: Record<string, number>;
    entrypoints_tls: number;
    backends: number;
    backends_unhealthy: number;
    diagnostics: { error: number; warn: number; info: number };
    acme_enabled: boolean;
  };
  proxy: {
    /** Unix timestamp (seconds) of the last successful Sōzu worker poll.
     *  `0` if no poll has succeeded yet. */
    last_poll_seconds: number;
    /** Sōzu-emitted counters/gauges, keyed by their original `sozu` name
     *  (dots become underscores). Values are integers; treat unknowns
     *  defensively. */
    metrics: Record<string, number>;
    /** Latency histogram for requests served through the Sōzune middleware
     *  layer (measured by Sōzune itself). Middleware-less routes are served
     *  directly by Sōzu and not counted. Optional so older servers (without
     *  this field) don't break the dashboard. */
    middleware_request_duration_seconds?: {
      /** `[upper_bound_seconds, cumulative_count]` pairs, ascending. */
      buckets: [string, number][];
      /** Sum of all observed request durations, in seconds. */
      sum: number;
      /** Total number of observed requests. */
      count: number;
    };
    /** Middleware-layer response counts by HTTP status class
     *  (`1xx`/`2xx`/`3xx`/`4xx`/`5xx`/`other`). Optional so older servers
     *  don't break the dashboard. */
    middleware_requests_by_status?: Record<string, number>;
  };
}

export function getMetrics(): Promise<MetricsView> {
  // `request()` always sends `Accept: application/json`, so the metrics
  // endpoint returns its JSON variant rather than the Prometheus text format.
  return request<MetricsView>('/metrics');
}

export function me(): Promise<{ name: string; role: 'admin' | 'read-only' }> {
  return request<{ name: string; role: 'admin' | 'read-only' }>('/me');
}
