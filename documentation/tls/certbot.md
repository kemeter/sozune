# Certbot

Sōzune can serve certificates that [certbot](https://certbot.eff.org) obtains and renews, through [certificates from files](/documentation/tls/overview#certificates-from-files). Use it when:

- your DNS provider has a certbot plugin but no [DNS-01 resolver](/documentation/tls/acme) in Sōzune, and you need a wildcard;
- certbot already manages your certificates and you want to keep it that way.

Certbot issues and renews; Sōzune only reads the files. ACME can stay enabled for your other hostnames: it never orders a certificate for a name a file already covers.

## 1. Obtain the certificate

With a DNS plugin, a single certificate can cover the apex and every subdomain:

```bash
certbot certonly \
  --authenticator <dns-plugin> \
  -d example.com -d '*.example.com'
```

Each plugin takes its own credential options: see its documentation, and certbot's [list of DNS plugins](https://eff-certbot.readthedocs.io/en/stable/using.html#dns-plugins).

Certbot writes the result under `/etc/letsencrypt/live/example.com/`. Sōzune needs two of those files:

| File | Content |
|---|---|
| `fullchain.pem` | The certificate followed by its intermediates. Use this one, not `cert.pem`: without the intermediates, clients cannot build the chain. |
| `privkey.pem` | The private key. |

## 2. Declare it in Sōzune

```yaml
proxy:
  https:
    tls:
      certificates:
        - cert_file: /etc/letsencrypt/live/example.com/fullchain.pem
          key_file: /etc/letsencrypt/live/example.com/privkey.pem
```

Routes do not reference the certificate. Turn TLS on as usual, and every hostname the certificate covers is served with it:

```yaml
labels:
  - "sozune.http.app.host=app.example.com"
  - "sozune.http.app.tls=true"
```

At startup, Sōzune logs each loaded file with the names it covers:

```
Loaded certificate /etc/letsencrypt/live/example.com/fullchain.pem for example.com, *.example.com
```

## 3. Run Sōzune in Docker

Mount the whole `/etc/letsencrypt` at the same path, read-only:

```yaml
services:
  sozune:
    image: ghcr.io/kemeter/sozune:latest
    container_name: sozune
    user: "0:0"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./config.yaml:/etc/sozune/config.yaml:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
```

The files in `live/` are symlinks into `../../archive/`. Mounting `live/` alone leaves them dangling, and Sōzune refuses to start because it cannot read them.

Certbot creates `privkey.pem` readable by root only, while the image runs as the unprivileged `nonroot` user (UID `65532`). `user: "0:0"` runs it as root so it can read the key. To keep `nonroot`, give UID `65532` read access to the key instead, and restore it after each renewal from the hook below, since certbot writes a new key every time.

## 4. Reload after each renewal

Certbot renews on its own, from a systemd timer or a cron job set up by its package. Sōzune reads the files once, at startup, so it must be restarted after each renewal. Certbot runs every executable in `/etc/letsencrypt/renewal-hooks/deploy/` after a successful renewal:

```bash
cat > /etc/letsencrypt/renewal-hooks/deploy/restart-sozune.sh <<'EOF'
#!/bin/sh
docker restart sozune
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-sozune.sh
```

`sozune` is the `container_name` set above. Without one, Compose names the container `<project>-sozune-1`: use `docker compose -f /path/to/compose.yaml restart sozune` instead. Outside Docker, `systemctl restart sozune` or whatever restarts your instance. The restart closes the connections in progress.

`certbot renew --dry-run` checks that renewal works, but skips deploy hooks: run the hook once by hand to check it.

## Check the served certificate

```bash
openssl s_client -connect example.com:443 -servername app.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName -enddate
```

`-servername` sets the SNI. Without it, the handshake asks for no name, and no certificate matches it.

## Troubleshooting

**`could not read cert_file`.** The path does not exist inside Sōzune's environment, or the user it runs as cannot read it. In Docker, check the `/etc/letsencrypt` mount (step 3).

**`the private key does not match the certificate`.** `cert_file` and `key_file` come from different certificates, usually two `live/` directories (`example.com` and `example.com-0001`). Take both files from the same directory.

**`the certificate has expired`.** Renewal has not run, or failed. Look at `certbot renew` and its logs in `/var/log/letsencrypt/`, then restart Sōzune.

**A hostname is not served with the certificate.** The certificate does not cover it. A `*.example.com` wildcard covers exactly one label: `app.example.com`, but neither `example.com` nor `a.b.example.com`. Add the missing names with `-d` and request the certificate again.
