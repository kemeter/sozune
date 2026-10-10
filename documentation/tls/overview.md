# TLS overview

Sōzune terminates TLS on its HTTPS listener. Certificates come from [ACME / Let's Encrypt](/documentation/tls/acme), or from [files you supply](#certificates-from-files).

## Enable TLS for a service

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.tls=true"
```

When `tls=true` and no [certificate from a file](#certificates-from-files) covers the hostname, Sōzune:

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

## Certificates from files

A certificate issued outside Sōzune — a wildcard from certbot, a purchased certificate, an internal PKI — is declared under `proxy.https.tls.certificates`:

```yaml
proxy:
  https:
    tls:
      certificates:
        - cert_file: /etc/letsencrypt/live/example.com/fullchain.pem
          key_file: /etc/letsencrypt/live/example.com/privkey.pem
```

| Field | Description |
|---|---|
| `cert_file` | PEM certificate, leaf first, followed by its intermediates (`fullchain.pem`). |
| `key_file` | PEM private key of that certificate. |

No route references a certificate: the handshake picks it by SNI, among the names it carries (its Subject Alternative Names, or its Common Name when it has none). A `tls=true` route on `app.example.com` is served with a `*.example.com` certificate, and ACME neither orders nor loads from its cache a certificate for a hostname such a certificate covers.

Every file is checked at startup. A path that cannot be read, a key that does not belong to the certificate, an expired or not-yet-valid certificate, or one naming no host stops Sōzune with an error naming the file.

**Read once, at startup.** Sōzune neither renews these certificates nor watches the files: restart it after replacing them. [Certbot](/documentation/tls/certbot) walks through the whole setup, renewal included.

The dashboard's Certificates page and [`GET /certificates`](/documentation/configuration/api#get-certificates) list these certificates with their expiry, and flag one whose file on disk has been replaced since startup. [`sozune doctor`](/documentation/advanced/debugging) checks each file and warns when a certificate is close to expiry.

**Docker.** Certbot's `live/` directory holds symlinks into `archive/`, so mount the whole `/etc/letsencrypt`, not `live/` alone. The files are readable by root only by default.

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

## Client certificates (mutual TLS)

Ask clients for a certificate during the handshake, and accept only those signed by a CA you trust:

```yaml
proxy:
  https:
    tls:
      client_auth:
        mode: required                   # none | optional | required
        ca_files:
          - /etc/sozune/client-ca.pem
        crl_files:                       # optional
          - /etc/sozune/client-crl.pem
```

| Field | Description |
|---|---|
| `mode` | `none`: no certificate is asked for. `optional`: a client without a certificate is admitted, a client with one must present a valid one. `required`: the handshake fails unless the client presents a valid certificate. |
| `ca_files` | PEM files of the CAs a client certificate must chain to. Required unless `mode` is `none`. |
| `crl_files` | PEM certificate revocation lists. Revocation is checked over the whole chain, and a certificate whose status cannot be established is refused. |

**Read once, at startup.** A CA or CRL file that cannot be read, holds no certificate or CRL, or a CRL past its `nextUpdate`, fails startup: Sōzune does not start with a weaker check than the one configured. Restart after replacing a file.

**Plain HTTP is redirected.** With `mode: required`, a `tls=true` route answers its plain HTTP requests with a redirect to HTTPS, as with `httpsRedirect=true`: served on port 80 as well, it would reach the backend without any certificate. A route without `tls` is not served over HTTPS and is not covered by client certificates.

**Listener-wide, and not an authorization.** Like versions and ciphers, it applies to every route on the HTTPS port. A valid certificate admits its client to all of them, and the backend does not learn which certificate the client presented: `optional` alone restricts nothing. Put routes that need different client policies behind different instances.

## What's not configurable

- Per-route TLS options — versions, ciphers and client certificates are a property of the listener, not the route (see above).
- Forwarding the client certificate, or its subject, to the backend.
- Reloading [certificates from files](#certificates-from-files) without a restart.
