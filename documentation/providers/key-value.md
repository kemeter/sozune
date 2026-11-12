# Key-value providers

> Since 0.17

The etcd and Redis providers read routes from the keys of a store. Whatever writes the keys (a deploy script, a control plane, `etcdctl`) defines the routes, and Sōzune follows the keys as they change. The Redis provider works with [Valkey](https://valkey.io) too: Valkey speaks the Redis protocol.

## Layout

Under the root key (`sozune` by default), each service has its labels and its servers:

```text
sozune/<service>/labels/<label>  = <value>
sozune/<service>/servers/<name>  = <ip>[:<port>]
```

- **Labels** are the labels a container would carry, under the same names: `sozune.http.web.host`, `sozune.http.web.middlewares`, `sozune.tcp.db.port`… Every option of the [Docker labels](/documentation/providers/docker) works.
- **Servers** are the backends of the service's routes, one per key, as each replica of a container is one. A server is an IP address (`10.0.0.5`, `fd00::2`), with an optional port (`10.0.0.5:8080`, `[fd00::2]:8080`). A hostname is refused: a backend is an address.
- A server's port is the backend port of every service of its labels that sets no `port`. An explicit `sozune.<proto>.<svc>.port` wins. A server without a port takes the label's, else `80`.
- A service without a server is not routed. A key outside this layout is ignored and logged once, with the reason. A key whose value is no text (in Redis, a hash or a list) is left out.

The services of a store are routed without `sozune.enable=true`: keys are only written to be routed. Set `expose_by_default: false` to require it.

### Example

```bash
etcdctl put sozune/web/labels/sozune.http.web.host app.example.com
etcdctl put sozune/web/labels/sozune.http.web.middlewares compress
etcdctl put sozune/web/servers/a 10.0.0.5:8080
etcdctl put sozune/web/servers/b 10.0.0.6:8080
```

`app.example.com` is served by both servers. `etcdctl del sozune/web/servers/b` takes one out, `etcdctl del --prefix sozune/web/` the route. With Redis, the same keys are written with `SET`:

```bash
redis-cli SET sozune/web/labels/sozune.http.web.host app.example.com
redis-cli SET sozune/web/servers/a 10.0.0.5:8080
```

## How changes are seen

The tree is read again every `poll_interval` seconds (5 by default): etcd's in one request, Redis's with `SCAN` and `MGET`. Sōzune reloads only when the routes it gives change, so a short interval is cheap. A poll that fails (the store is down, a login is refused) is logged and changes nothing: the routes of the last poll keep being served.

## etcd

```yaml
providers:
  etcd:
    enabled: true
    endpoint: "https://etcd.internal:2379"
    root_key: "sozune"
    username: "sozune"
    # password: set SOZUNE_PROVIDER_ETCD_PASSWORD
    tls:
      ca: /etc/sozune/etcd-ca.pem
      cert: /etc/sozune/etcd-client.pem
      key: /etc/sozune/etcd-client-key.pem
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the etcd provider |
| `endpoint` | `http://127.0.0.1:2379` | Client URL of an etcd v3 member |
| `root_key` | `sozune` | Prefix of the keys read |
| `username` / `password` | `""` | User of etcd's authentication. Sōzune logs in, and logs in again when etcd stops taking its token |
| `tls.ca` | none | PEM file of the CA that signed etcd's certificate, trusted on top of the system roots |
| `tls.cert` / `tls.key` | none | PEM client certificate and key, for an etcd that requires mTLS |
| `poll_interval` | `5` | Seconds between two reads |
| `expose_by_default` | `true` | Route the services without `sozune.enable=true` |

The `tls` settings need an `https://` endpoint. Sōzune reads through etcd's JSON API (`/v3/kv/range`), served on the client port of etcd 3.4 and later. The user needs read access to the range of `root_key`.

Env var overrides: `SOZUNE_PROVIDER_ETCD_ENABLED`, `SOZUNE_PROVIDER_ETCD_ENDPOINT`, `SOZUNE_PROVIDER_ETCD_ROOT_KEY`, `SOZUNE_PROVIDER_ETCD_USERNAME`, `SOZUNE_PROVIDER_ETCD_PASSWORD`, `SOZUNE_PROVIDER_ETCD_POLL_INTERVAL`, `SOZUNE_PROVIDER_ETCD_EXPOSE_BY_DEFAULT`.

## Redis and Valkey

```yaml
providers:
  redis:
    enabled: true
    endpoint: "rediss://redis.internal:6380/0"
    root_key: "sozune"
    username: "sozune"
    # password: set SOZUNE_PROVIDER_REDIS_PASSWORD
    tls:
      ca: /etc/sozune/redis-ca.pem
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the Redis provider |
| `endpoint` | `redis://127.0.0.1:6379` | `redis://host:port/db`, or `rediss://` for TLS |
| `root_key` | `sozune` | Prefix of the keys read |
| `username` / `password` | `""` | ACL user and password, overriding the URL's. A password alone logs in as `default` |
| `db` | the URL's, else `0` | Database number |
| `tls.ca` | none | PEM file of the CA that signed the server's certificate. When set, it is the only CA trusted |
| `tls.cert` / `tls.key` | none | PEM client certificate and key, for a server that requires mTLS |
| `poll_interval` | `5` | Seconds between two reads |
| `expose_by_default` | `true` | Route the services without `sozune.enable=true` |

The `tls` settings need a `rediss://` endpoint. The user needs the `SCAN` and `MGET` commands on the keys under `root_key` (`~sozune/* +scan +mget`). Redis Cluster and Sentinel are not supported: point the provider at a primary or a replica.

Env var overrides: `SOZUNE_PROVIDER_REDIS_ENABLED`, `SOZUNE_PROVIDER_REDIS_ENDPOINT`, `SOZUNE_PROVIDER_REDIS_ROOT_KEY`, `SOZUNE_PROVIDER_REDIS_USERNAME`, `SOZUNE_PROVIDER_REDIS_PASSWORD`, `SOZUNE_PROVIDER_REDIS_DB`, `SOZUNE_PROVIDER_REDIS_POLL_INTERVAL`, `SOZUNE_PROVIDER_REDIS_EXPOSE_BY_DEFAULT`.

## Checking a store

`sozune validate --provider etcd` (or `redis`) reads the store once and shows the routes each server gives, with the keys it ignores and why. `sozune doctor` checks that the endpoint is reachable.
