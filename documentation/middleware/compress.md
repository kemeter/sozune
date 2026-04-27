# Gzip compression

Compress backend responses with gzip before sending them to the client. Opt-in per service.

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

## When compression kicks in

A response is compressed only if **all** of the following are true:

1. The service has `compress=true`.
2. The client sent `Accept-Encoding` containing `gzip`.
3. The response `Content-Type` is in the compressible list (see below).
4. The response is not already encoded (no existing `Content-Encoding`).

Otherwise the response is forwarded untouched.

## Compressible content types

The check is a substring match against the response `Content-Type`:

`text/*`, `application/json`, `application/javascript`, `application/xml`, `application/xhtml`, `application/rss`, `application/atom`, `image/svg`

Anything else (binary, images, video, archives) is forwarded as-is.

## Headers added

When a response is compressed, Sozune:

- Sets `Content-Encoding: gzip`
- Recomputes `Content-Length`
- Removes `Transfer-Encoding` (the response is fully buffered before sending)

## Body size cap

To bound memory, the response body must fit in **10 MiB** in memory before being compressed. A larger body returns `502 Bad Gateway` to the client.

If you serve large compressible payloads (long log streams, large JSON dumps), turn compression off for that service and rely on the backend to compress.

## Compression level

Sozune uses gzip level 1 (`Compression::fast()`). It optimises for speed over ratio — adequate for typical API/HTML payloads, sub-millisecond on small responses.

## Limitations

- **Gzip only.** No `br` (Brotli), no `zstd`.
- **No streaming.** The body is buffered, compressed, then sent. Combined with the 10 MiB cap, this rules out streaming responses larger than that.
