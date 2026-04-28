# Basic auth

Protect a route with HTTP Basic Authentication. Sozune validates credentials against a list of `username:password_hash` pairs configured per service.

## Label

```yaml
labels:
  - "sozune.http.<svc>.auth.basic=<user>:<hash>[,<user>:<hash>...]"
```

Multiple users are comma-separated.

## Password format

The password must be supplied as a **lowercase hex SHA-256** of the plaintext password. The hash is compared in constant-time on every authenticated request, so a fast hash is required at the proxy layer.

```yaml
labels:
  # admin / secret
  - "sozune.http.app.auth.basic=admin:2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"

  # multiple users
  - "sozune.http.app.auth.basic=alice:5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5,bob:7cb6efb98ba5972a9b5090dc2e517fe14d12cb04f905d4eeb2bbb5a5b1b8a2dc"
```

## Generating the hash

```bash
echo -n 'secret' | sha256sum | awk '{print $1}'
# 2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b
```

The `-n` flag is essential — without it, `echo` appends a newline and the hash will not match.

## Custom realm

The `WWW-Authenticate` realm presented to the client on a `401` response defaults to a generic value. Override it with:

```yaml
labels:
  - "sozune.http.app.wwwAuthenticate=Admin Area"
```

The client will see `WWW-Authenticate: Basic realm="Admin Area"`.

## Behaviour

- Missing `Authorization` header → `401 Unauthorized`
- Scheme other than `Basic` (e.g. `Bearer`) → `401`
- Malformed base64 or `username:password` payload → `401`
- Unknown username or wrong password → `401`
- Match → request is forwarded to the backend.

## Security notes

- Comparisons are **constant-time** to mitigate timing attacks.
- Basic auth sends credentials base64-encoded but **not encrypted**. Always combine with TLS (`tls=true` + `httpsRedirect=true`).
- Treat your label source (Compose file, Swarm secret, etc.) as a credential store — anyone who can read the SHA-256 hash can brute-force a weak password offline. Use long random passwords.
