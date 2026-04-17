const TOKEN_KEY = 'sozune.token';
const BASE_URL_KEY = 'sozune.baseUrl';
const DEFAULT_BASE_URL = 'http://127.0.0.1:3035';

export function getToken(): string | null {
  if (typeof localStorage === 'undefined') {
    return null;
  }
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  if (typeof localStorage === 'undefined') {
    return;
  }
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

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

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const res = await fetch(`${getBaseUrl()}${path}`, { ...init, headers });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${res.status} ${res.statusText}${text ? `: ${text}` : ''}`);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

export type Protocol = 'Http' | 'Tcp' | 'Udp';

export interface EntrypointConfig {
  hostnames: string[];
  port: number;
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

export interface Entrypoint {
  id: string;
  name: string;
  protocol: Protocol;
  backends: string[];
  config: EntrypointConfig;
  source?: string | null;
  backend_weights?: Record<string, number>;
}

export function listEntrypoints(): Promise<Entrypoint[]> {
  return request<Entrypoint[]>('/entrypoints');
}

export function getEntrypoint(id: string): Promise<Entrypoint> {
  return request<Entrypoint>(`/entrypoints/${encodeURIComponent(id)}`);
}

export function health(): Promise<unknown> {
  return request<unknown>('/health');
}
