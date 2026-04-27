# Basic auth

Protect a route with HTTP Basic Authentication. Sozune validates credentials against a list of `username:password_hash` pairs configured per service.

## Label

```yaml
labels:
  - "sozune.http.<svc>.auth.basic=<user>:<hash>[,<user>:<hash>...]"
```

Multiple users are comma-separated.

## Password format

Two formats are accepted:

- **bcrypt** (recommended) — hashes prefixed with `$2b$`, `$2a$`, or `$2y$`.
- **plaintext** (legacy) — accepted as-is, no hashing.

```yaml
labels:
  # bcrypt — recommended
  - "sozune.http.app.auth.basic=admin:$2b$12$KIXxPfn..."

  # plaintext — legacy, avoid in production
  - "sozune.http.app.auth.basic=admin:secret"

  # multiple users
  - "sozune.http.app.auth.basic=alice:$2b$12$...,bob:$2b$12$..."
```

## Generating a bcrypt hash

```bash
htpasswd -nbBC 12 admin secret
# admin:$2y$12$...

# In Compose YAML, escape every '$' as '$$':
# - "sozune.http.app.auth.basic=admin:$$2y$$12$$..."
```

## Behaviour

- Missing `Authorization` header → `401 Unauthorized`
- Scheme other than `Basic` (e.g. `Bearer`) → `401`
- Malformed base64 or `username:password` payload → `401`
- Unknown username or wrong password → `401`
- Match → request is forwarded to the backend.

The `401` response carries `WWW-Authenticate: Basic realm="restricted"`.

## Security notes

- Username and password comparisons are **constant-time** to mitigate timing attacks.
- Basic auth sends credentials base64-encoded but **not encrypted**. Always combine with TLS.
- Plaintext password support exists for backwards compatibility only — prefer bcrypt.
