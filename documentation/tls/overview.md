# TLS overview

Sōzune terminates TLS on its HTTPS listener. Certificates come from [ACME / Let's Encrypt](/documentation/tls/acme).

## Enable TLS for a service

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.tls=true"
```

When `tls=true`, Sōzune:

1. Adds the hostname to the list of names needing a certificate.
2. Triggers ACME provisioning for the hostname (HTTP-01 challenge).
3. Hot-loads the certificate into the HTTPS listener once issued.
4. Renews automatically before expiration.

## HTTP/2

HTTP/2 is enabled out of the box: TLS ALPN advertises both `h2` and `http/1.1`, so clients that support h2 get h2 and the rest fall back to HTTP/1.1.

You can override the ALPN negotiation through the `proxy.https.http2` config block. Leaving it unset keeps the default above.

```yaml
proxy:
  https:
    http2:
      # ALPN protocols advertised on the listener. Valid values: "h2", "http/1.1".
      # Omit to keep the default ["h2", "http/1.1"].
      alpn_protocols: ["h2", "http/1.1"]
      # Disable HTTP/1.1 on the listener (h2-only). Defaults to false.
      disable_http11: false
```

Common setups:

| Goal | Config |
|---|---|
| Default (h2 + HTTP/1.1) | omit the `http2` block |
| Force HTTP/1.1 only (disable h2) | `alpn_protocols: ["http/1.1"]` |
| HTTP/2 only (no HTTP/1.1 fallback) | `alpn_protocols: ["h2"]` and `disable_http11: true` |

> `disable_http11: true` together with `http/1.1` in `alpn_protocols` is rejected at startup — the listener would advertise a protocol it then refuses, which is a self-inflicted denial of service.

## SNI

Sōzune supports SNI natively (inherited from Sōzu). Many domains, each with its own certificate, share the same listener.

The name serves two distinct purposes, depending on the entrypoint:

- **On an HTTPS entrypoint**, Sōzune terminates TLS and uses the name to pick which certificate to present. That is the case described above.
- **On a TCP entrypoint**, TLS is never terminated. Sōzune reads the name to choose a backend and forwards the encrypted bytes untouched; the client's handshake completes with the backend, against the backend's certificate. See [Route by SNI](/documentation/routing/tcp#route-by-sni-tls-passthrough).

Use the first when Sōzune should own the certificates, the second when the backend must.

## HTTPS redirect

Force HTTP traffic to HTTPS — see [Redirects](/documentation/middleware/redirects).

## TLS versions and ciphers

Harden the HTTPS listener under `proxy.https.tls`. All fields are optional; each absent one keeps Sōzu's default.

```yaml
proxy:
  https:
    listen_address: 443
    tls:
      min_version: "1.3"        # refuse TLS 1.2 entirely
      max_version: "1.3"        # optional upper bound (>= min_version)
      ciphers:                  # rustls names, both TLS 1.2 and 1.3 suites
        - "TLS13_AES_256_GCM_SHA384"
        - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
```

| Field | Description |
|---|---|
| `min_version` | Lowest TLS version accepted: `"1.2"` or `"1.3"`. |
| `max_version` | Highest accepted, same values; must be `>= min_version`. |
| `ciphers` | Allowed cipher suites, by **rustls** name — both TLS 1.3 (`TLS13_*`) and TLS 1.2 (`TLS_ECDHE_*`) go in this one list. |

**`ciphers` is a single list across both versions.** It maps to the only cipher input Sōzu's worker reads, so listing only TLS 1.2 suites leaves no TLS 1.3 suite enabled — include the 1.3 suites you want too. An unrecognised name is dropped with a log line; an all-unrecognised list fails the HTTPS worker at startup.

**These are listener-wide.** Sōzu applies versions and ciphers at bind time, so every hostname served on the HTTPS port shares them — they cannot vary per route. An invalid version (unknown value, `max_version` below `min_version`) fails startup rather than being silently ignored.

## What's not configurable

- Per-route TLS options — versions and ciphers are a property of the listener, not the route (see above).
- Manual certificate injection — ACME is the only source. There is no path to provide a self-signed cert, a wildcard purchased elsewhere, or a cert managed by another tool.
