# TLS overview

Sozune terminates TLS on its HTTPS listener. Certificates come from [ACME / Let's Encrypt](/documentation/tls/acme).

## Enable TLS for a service

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.tls=true"
```

When `tls=true`, Sozune:

1. Adds the hostname to the list of names needing a certificate.
2. Triggers ACME provisioning for the hostname (HTTP-01 challenge).
3. Hot-loads the certificate into the HTTPS listener once issued.
4. Renews automatically before expiration.

## HTTP/2

HTTP/2 is enabled out of the box: TLS ALPN advertises both `h2` and `http/1.1`, so clients that support h2 get h2 and the rest fall back to HTTP/1.1. ALPN behaviour is delegated to Sōzu's listener defaults — Sozune does not currently expose ALPN configuration of its own.

## SNI

Sozune supports SNI natively (inherited from Sōzu). Many domains, each with its own certificate, share the same listener.

## HTTPS redirect

Force HTTP traffic to HTTPS — see [Redirects](/documentation/middleware/redirects).

## What's not configurable

The following are not currently exposed by Sozune; they fall back to Sōzu defaults:

- Cipher suites
- Minimum TLS version
- ALPN protocol list (always `h2, http/1.1`)
- Manual certificate injection — ACME is the only source. There is no path to provide a self-signed cert, a wildcard purchased elsewhere, or a cert managed by another tool.
