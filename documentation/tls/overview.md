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

## HTTPS redirect

Force HTTP traffic to HTTPS — see [Redirects](/documentation/middleware/redirects).

## What's not configurable

The following are not currently exposed by Sōzune; they fall back to Sōzu defaults:

- Cipher suites
- Minimum TLS version
- Manual certificate injection — ACME is the only source. There is no path to provide a self-signed cert, a wildcard purchased elsewhere, or a cert managed by another tool.
