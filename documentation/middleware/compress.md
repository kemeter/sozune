# Response compression

Compress backend responses before sending them to the client. Opt-in per service.

Supported algorithms: **zstd**, **brotli (br)**, **gzip**.

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

Sozune picks the best encoding the client accepts, in this order of preference:

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

When a response is compressed, Sozune:

- Sets `Content-Encoding` to the chosen algorithm (`zstd`, `br`, or `gzip`).
- Recomputes `Content-Length`.
- Removes `Transfer-Encoding` (the response is fully buffered before sending).

## Body size cap

To bound memory, the response body must fit in **10 MiB** in memory before being compressed. A larger body returns `502 Bad Gateway` to the client.

If you serve large compressible payloads (long log streams, large JSON dumps), turn compression off for that service and rely on the backend to compress.

## Compression levels

Sozune favours speed over ratio for live traffic:

| Algorithm | Level | Notes |
|---|---|---|
| gzip | 1 (`fast`) | Sub-millisecond on small payloads. |
| brotli | 4 | Fast end of brotli's range, still ~10–20% better than gzip. |
| zstd | 3 | zstd's default; matches gzip speed with brotli-class ratio. |

These levels are not configurable today.

## Limitations

- **No streaming.** The body is buffered, compressed, then sent. Combined with the 10 MiB cap, this rules out streaming responses larger than that.
- **No deflate.** Considered obsolete and not supported.
- **Compression levels are fixed.** No knob to trade speed for ratio per service yet.
