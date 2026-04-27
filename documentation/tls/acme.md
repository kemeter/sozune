# ACME / Let's Encrypt

Sozune provisions and renews TLS certificates automatically through ACME (Let's Encrypt). Triggered the moment a service is declared with `tls=true`.

## Configuration

```yaml
acme:
  enabled: true
  email: "ops@example.com"
  certs_dir: "/etc/sozune/certs"
  staging: true
  challenge_port: 3036
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Master switch. If false, `tls=true` does nothing — connections will fail. |
| `email` | `""` | Contact email registered with the ACME account. Optional but strongly recommended (Let's Encrypt uses it for expiry notices). |
| `certs_dir` | `/etc/sozune/certs` | Where certificates and the ACME account credentials are stored. |
| `staging` | `true` | Use Let's Encrypt's staging environment (no rate limit, untrusted certs). **Switch to `false` for production.** |
| `challenge_port` | `3036` | Port where Sozune answers HTTP-01 challenges (loopback only). |

Every field is overridable through `SOZUNE_ACME_*` environment variables.

## How it works

When you declare a service with `tls=true`, Sozune scans every TLS-enabled hostname and triggers an HTTP-01 challenge for each one that is missing a certificate or is expiring within 30 days.

```
   tls=true on app.example.com
            │
            ▼
   ┌──────────────────────┐
   │ ACME order created   │
   │ (Let's Encrypt)      │
   └──────┬───────────────┘
          │
          ▼  GET /.well-known/acme-challenge/<token>
   ┌──────────────────────────────┐
   │ Sōzu routes the challenge    │
   │ to challenge_port (loopback) │
   └──────┬───────────────────────┘
          │
          ▼
   ┌────────────────┐
   │ Token validated │
   └──────┬─────────┘
          │
          ▼
   Cert delivered, saved to disk,
   hot-loaded into the HTTPS listener.
```

The `/.well-known/acme-challenge/` path is registered as a high-priority route on every HTTP listener, so HTTP-01 always works regardless of your service routing.

## Renewal

- **Initial provisioning** runs at startup (after loading any existing certs from disk).
- **Periodic check** every 12 hours.
- **On-demand check** when an entrypoint is added or modified — Sozune is notified through an internal channel and re-runs the provisioning logic 2 seconds later.
- **Renewal threshold:** a certificate is renewed when it expires within 30 days.

A certificate that is already valid for more than 30 days is left untouched.

## Storage layout

```
<certs_dir>/
├── account_credentials.json     # ACME account private key (mode 0600)
├── app.example.com/
│   ├── cert.pem                 # Leaf cert + chain
│   └── key.pem                  # Private key (mode 0600)
└── api.example.com/
    ├── cert.pem
    └── key.pem
```

- One subdirectory per hostname.
- Filenames are fixed: `cert.pem` (full chain) and `key.pem`.
- Persisting `certs_dir` across restarts is what avoids re-issuing certs at every boot. **Always mount it on a volume in production** — Let's Encrypt enforces rate limits on new orders.

## Production checklist

1. Set `staging: false`.
2. Set a real `email`.
3. Mount `certs_dir` on a persistent volume.
4. Open inbound TCP port 80 — required for HTTP-01 challenges to reach Sozune.
5. Make sure DNS for every TLS-enabled hostname resolves to the Sozune host.

## Existing certificates at startup

When Sozune starts, it scans `certs_dir` and loads every cert that is not expired. Each loaded cert is pushed to Sōzu so traffic can be served immediately, before the renewal loop runs.

If a cert is expired, it is skipped. The renewal loop will issue a new one shortly after.

## Hostname validation

Every TLS hostname is validated before it's used as a directory name. Names containing `/`, `\`, null bytes, `..`, or equal to `.` / `..` are rejected with a warning. This prevents an adversarial label from writing outside `certs_dir`.

## Limitations

- **HTTP-01 only.** No DNS-01. Wildcards (`*.example.com`) cannot be issued by Let's Encrypt with HTTP-01 — they require DNS-01. A wildcard hostname declared with `tls=true` will fail to provision.
- **Let's Encrypt only.** The ACME directory URL is hardcoded. No support for custom ACME providers (ZeroSSL, Buypass, internal CA, Pebble for testing).
- **No manual certificate path.** You cannot inject a cert managed externally (purchased, self-signed, internal PKI). ACME is the only source.
- **No EAB.** No External Account Binding — incompatible with ACME providers that require it.
- **Single account.** One ACME account is used for all certificates, stored at `certs_dir/account_credentials.json`. If the file is corrupt, Sozune creates a new account on the next start.

## Troubleshooting

**Certificate not issued, no error logged.** Check that `acme.enabled: true`. With it off, `tls=true` is silently a no-op.

**HTTP-01 challenge fails.** The challenge is served on `127.0.0.1:<challenge_port>` and routed by Sōzu through the public HTTP listener (port 80 by default). Make sure:
- Port 80 is open and reachable from the public Internet.
- DNS resolves to the Sozune host.
- No other software is listening on `challenge_port` on the same host.

**`Order still pending after 30 retries`.** The CA didn't validate the challenge in 2.5 minutes. Almost always a network/DNS issue — Let's Encrypt couldn't reach `http://<your-host>/.well-known/acme-challenge/<token>`.

**`Loaded existing certificate for X` then a new request appears.** Sozune found the cert on disk but the renewal logic decided it needs renewal (less than 30 days remaining). Expected.
