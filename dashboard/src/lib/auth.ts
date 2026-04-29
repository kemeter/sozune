import { type Readable, writable } from 'svelte/store';

const CREDENTIALS_KEY = 'sozune.credentials';

export type Role = 'admin' | 'read-only';

export interface Identity {
  name: string;
  role: Role;
}

interface StoredCredentials {
  name: string;
  password: string;
  role: Role;
}

function readSession(): StoredCredentials | null {
  if (typeof sessionStorage === 'undefined') {
    return null;
  }
  const raw = sessionStorage.getItem(CREDENTIALS_KEY);
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(raw) as StoredCredentials;
  } catch {
    return null;
  }
}

function writeSession(value: StoredCredentials | null): void {
  if (typeof sessionStorage === 'undefined') {
    return;
  }
  if (value) {
    sessionStorage.setItem(CREDENTIALS_KEY, JSON.stringify(value));
  } else {
    sessionStorage.removeItem(CREDENTIALS_KEY);
  }
}

const initial = readSession();
const internal = writable<StoredCredentials | null>(initial);

/** Public read-only view of the current identity (no password). */
export const identity: Readable<Identity | null> = {
  subscribe: (run) => internal.subscribe((c) => run(c ? { name: c.name, role: c.role } : null))
};

export function setAuth(name: string, password: string, role: Role): void {
  const value = { name, password, role };
  writeSession(value);
  internal.set(value);
}

export function clearAuth(): void {
  writeSession(null);
  internal.set(null);
}

/** Returns the raw credentials needed to forge `Authorization: Basic`. */
export function getCredentials(): { name: string; password: string } | null {
  const c = readSession();
  return c ? { name: c.name, password: c.password } : null;
}

export function isAuthenticated(): boolean {
  return readSession() !== null;
}
