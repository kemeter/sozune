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
  [key: string]: unknown;
}

export interface Backend {
  address: string;
  port: number;
  weight: number;
}

/** Backend identifier as serialized in `unhealthy_backends`: `address:port`. */
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

export interface Entrypoint {
  id: string;
  name: string;
  protocol: Protocol;
  backends: Backend[];
  config: EntrypointConfig;
  source?: string | null;
  /** Backend addresses (`host:port`) currently marked down by the health checker. */
  unhealthy_backends?: string[];
  /** Diagnostics produced for this entrypoint by the label parser. */
  diagnostics?: Diagnostic[];
}

export interface DiagnosticsResponse {
  total: number;
  items: { candidate_id: string; diagnostics: Diagnostic[] }[];
}

export function listEntrypoints(): Promise<Entrypoint[]> {
  return request<Entrypoint[]>('/entrypoints');
}

export function listDiagnostics(): Promise<DiagnosticsResponse> {
  return request<DiagnosticsResponse>('/diagnostics');
}

export function getEntrypoint(id: string): Promise<Entrypoint> {
  return request<Entrypoint>(`/entrypoints/${encodeURIComponent(id)}`);
}

export function health(): Promise<unknown> {
  return request<unknown>('/health');
}

export function me(): Promise<{ name: string; role: 'admin' | 'read-only' }> {
  return request<{ name: string; role: 'admin' | 'read-only' }>('/me');
}
