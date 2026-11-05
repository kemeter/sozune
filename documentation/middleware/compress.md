# Response compression

> Since 0.11

Compress backend responses before sending them to the client. Opt-in per service.

Supported algorithms: **zstd** (since 0.12), **brotli (br)** (since 0.12), **gzip**.

## Label

```yaml
labels:
  - "sozune.http.<svc>.compress=true"
```

## Example

```yaml
labels:
  - "sozune.http.api.host=api.example.com"
  - "sozune.http.api.compress=true"
```

## Algorithm selection

Sōzune picks the best encoding the client accepts, in this order of preference:

1. `zstd`
2. `br` (Brotli)
3. `gzip`

The client's `Accept-Encoding` header drives the choice. If none of the three are listed, the response is forwarded uncompressed.

```
Accept-Encoding: gzip, br, zstd  →  Content-Encoding: zstd
Accept-Encoding: gzip, br        →  Content-Encoding: br
Accept-Encoding: gzip            →  Content-Encoding: gzip
Accept-Encoding: deflate         →  (no compression)
```

`q=` quality values are ignored — the priority order above always wins.

## When compression kicks in

A response is compressed only if **all** of the following are true:

1. The service has `compress=true`.
2. The client sent `Accept-Encoding` with `zstd`, `br`, or `gzip`.
3. The response `Content-Type` is in the compressible list (see below).
4. The response is not already encoded (no existing `Content-Encoding`).

Otherwise the response is forwarded untouched.

## Compressible content types

The check is a substring match against the response `Content-Type`:

`text/*`, `application/json`, `application/javascript`, `application/xml`, `application/xhtml`, `application/rss`, `application/atom`, `image/svg`

Anything else (binary, images, video, archives) is forwarded as-is.

## Headers added

When a response is compressed, Sōzune:

- Sets `Content-Encoding` to the chosen algorithm (`zstd`, `br`, or `gzip`).
- Removes `Content-Length`: the compressed body is streamed, its length not known ahead.

## Streaming

The body is compressed as it comes from the backend, part by part, each part sent on to the client at once: a large response is never held in memory, and a stream (Server-Sent Events, a long log tail) reaches the client as it goes. Trailers follow the compressed body (since 0.16; the body was read whole first, up to 10 MiB, before).

## Compression levels

Sōzune favours speed over ratio for live traffic:

| Algorithm | Level | Notes |
|---|---|---|
| gzip | 1 (`fast`) | Sub-millisecond on small payloads. |
| brotli | 4 | Fast end of brotli's range, still ~10–20% better than gzip. |
| zstd | 3 | zstd's default; matches gzip speed with brotli-class ratio. |

These levels are not configurable today.

## Limitations

- **No deflate.** Considered obsolete and not supported.
- **Compression levels are fixed.** No knob to trade speed for ratio per service yet.
