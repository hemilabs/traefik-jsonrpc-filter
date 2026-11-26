# traefik-jsonrpc-filter

[![Go Reference](https://pkg.go.dev/badge/github.com/hemilabs/traefik-jsonrpc-filter.svg)](https://pkg.go.dev/github.com/hemilabs/traefik-jsonrpc-filter)
[![Go Report Card](https://goreportcard.com/badge/github.com/hemilabs/traefik-jsonrpc-filter)](https://goreportcard.com/report/github.com/hemilabs/traefik-jsonrpc-filter)
[![MIT License](https://img.shields.io/badge/license-MIT-ff6c15)](LICENSE)

A [Traefik](https://traefik.io) middleware plugin that filters [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
requests by method name.

- **Block or allow methods.** Reject specific methods, or permit only known-good methods, or combine both.
- **Pattern matching.** Use exact match, `prefix*`, `*suffix`, `*contains*` or `regex:<expr>`.
- **Batch support.** Inspects every element of a JSON-RPC batch array.
- **Custom JSON-RPC errors.** Configure JSON-RPC error code, message, and data globally or per-blocked-method.
- **Configurable controls.** Configure the maximum request body size, max batch size, optionally restrict to POST-only
  or configure which HTTP methods pass through uninspected (e.g. `OPTIONS` for CORS).
- **Fail closed.** Malformed JSON requests, missing `method` fields, and oversized bodies are rejected.

## Installation

Add the plugin to your Traefik static configuration:

```yaml
# traefik.yml (static configuration)
experimental:
  plugins:
    jsonrpc-filter:
      moduleName: github.com/hemilabs/traefik-jsonrpc-filter
      version: v0.1.0  # use the latest version
```

## Configuration

All configuration options with their defaults:

| Option                   | Type              | Default           | Description                                                                                  |
|--------------------------|-------------------|-------------------|----------------------------------------------------------------------------------------------|
| `blockedMethods`         | `[]BlockedMethod` | -                 | Method patterns to reject (evaluated first). Each entry may include a custom error.          |
| `allowedMethods`         | `[]string`        | -                 | Patterns to permit (evaluated after blocked).                                                |
| `maxBodyBytes`           | `int64`           | `1048576` (1 MiB) | Max request body size in bytes.                                                              |
| `maxBatchSize`           | `int`             | `100`             | Max elements in a request JSON-RPC batch array.                                              |
| `blockStatusCode`        | `int`             | `403`             | HTTP status code for rejected requests (4xx/5xx).                                            |
| `blockError`             | `JSONRPCError`    | see below         | Default JSON-RPC error returned for rejected requests.                                       |
| `badRequestStatusCode`   | `int`             | `400`             | HTTP status code for malformed/oversized requests (4xx/5xx).                                 |
| `badRequestError`        | `JSONRPCError`    | see below         | JSON-RPC error returned for malformed/oversized requests.                                    |
| `restrictHTTPMethods`    | `bool`            | `false`           | When `true`, reject all non-POST requests with HTTP 405 and ignore `passthroughHTTPMethods`. |
| `passthroughHTTPMethods` | `[]string`        | `["OPTIONS"]`     | HTTP methods that bypass inspection (ignored when `restrictHTTPMethods` is true).            |

At least one of `blockedMethods` or `allowedMethods` must be configured.

Requests using a `passthroughHTTPMethods` method are not inspected, so they are rejected with `badRequestError` if they
have a body. Upstreams such as go-ethereum execute a JSON-RPC body regardless of the HTTP method.

### `BlockedMethod`

Each entry in `blockedMethods` is an object:

| Field        | Type           | Description                                                                       |
|--------------|----------------|-----------------------------------------------------------------------------------|
| `pattern`    | `string`       | Pattern to match (see [Pattern Matching](#pattern-matching)).                     |
| `statusCode` | `int`          | HTTP status code override. Defaults to `blockStatusCode` if unset.                |
| `error`      | `JSONRPCError` | Optional per-method JSON-RPC error override. Falls back to `blockError` if unset. |

### `JSONRPCError`

A [JSON-RPC 2.0 error object](https://www.jsonrpc.org/specification#error_object).

| Field     | Type     | Default                                      | Description               |
|-----------|----------|----------------------------------------------|---------------------------|
| `code`    | `int`    | `-32601` (block) / `-32600` (bad)            | JSON-RPC error code.      |
| `message` | `string` | `"method not allowed"` / `"invalid request"` | Short error description.  |
| `data`    | `any`    | -                                            | Optional additional data. |

Errors whose `data` cannot be encoded as JSON (e.g. a `map[any]any`) are rejected when the configuration is loaded.

The response body sent to clients has the shape:

```json
{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not allowed"},"id":1}
```

## Batch Requests

Batches are inspected element-by-element. The plugin operates **fail-closed**: if any element matches a blocked
pattern (or, in allowlist mode, matches no allowed pattern), the entire batch is rejected.

**Notes:**

- The rejection response is a **single** JSON-RPC error object containing the id of the first offending element.
  This is not a fully spec-compliant batch response (the spec calls for an array with one entry per request), but it
  is the most useful signal the filter can produce: the middleware never forwards any element of a rejected batch, so
  it cannot generate responses for the elements that would have been allowed.
- Batches exceeding `maxBatchSize` are rejected with `badRequestError`.

## Example

```yaml
# dynamic configuration
http:
  middlewares:
    jsonrpc-filter:
      plugin:
        jsonrpc-filter:
          blockedMethods:
            - pattern: "debug_*"
            - pattern: "admin_*"
            - pattern: "eth_sendRawTransaction"
              error:
                code: -32000
                message: "writes are disabled on this endpoint"
            - pattern: "coffee_brew"
              statusCode: 418
          allowedMethods:
            - "eth_*"
            - "net_*"
            - "op_*"
          maxBatchSize: 50
          maxBodyBytes: 1048576
          blockStatusCode: 403
          badRequestStatusCode: 400
          restrictHTTPMethods: false
          passthroughHTTPMethods:
            - OPTIONS
```

## Pattern Matching

Methods are matched against patterns in the following order:

1. **Blocked methods** are checked first - if any pattern matches, the request is rejected.
2. **Allowed methods** (if configured) are checked next - the method must match at least one pattern, or it is rejected.

Supported pattern types:

| Pattern  | Example                           | Matches                                   |
|----------|-----------------------------------|-------------------------------------------|
| Exact    | `test_call`                       | Only `test_call`                          |
| Prefix   | `debug_*`                         | `debug_special`, `debug_traceCall`, …     |
| Suffix   | `*_admin`                         | `app_admin`, `net_admin`, …               |
| Contains | `*debug*`                         | `special_debug_trace`, `my_debug_call`, … |
| Regex    | `regex:app_(event\|estimateCost)` | `app_event`, `app_estimateCost`           |

> [!NOTE]
> Regex patterns are automatically anchored as `^(?:<expr>)$` to prevent accidental partial matches. The anchors
> apply to the whole expression, so `regex:debug_.*|admin_.*` matches `admin_foo` but not `x_admin_foo`.

**Notes:**

- Methods are matched after JSON decoding, so `"debug_\u0074race"` is matched as `debug_trace`. No Unicode
  normalisation or trimming is performed.
- Exact and glob patterns compare raw bytes and are case-sensitive. Regex patterns use Go's
  [`regexp` syntax](https://pkg.go.dev/regexp/syntax), which matches Unicode code points (e.g. `.` matches `é`) and
  supports flags such as `(?i)` for case-insensitive matching.
- Decoded method names may contain control characters, such as a NUL byte from `"\u0000"`. If an upstream treats
  method names as NUL-terminated strings, restrict allowed methods to a safe character set, e.g.
  `regex:[A-Za-z0-9_]+`.
- Lone UTF-16 surrogates (e.g. `"\uD83D"`) and invalid UTF-8 are replaced with U+FFFD before matching, while the
  original bytes are forwarded unchanged. Upstreams using a JSON decoder that handles these differently than Go's
  `encoding/json` may see a different method name than the filter did.
- `*` and `**` match every method, including an empty method name.
- Empty patterns and patterns with leading or trailing whitespace (including after the `regex:` prefix) are rejected
  when the configuration is loaded, as they would otherwise never match.

## Request Inspection

The plugin only inspects the top-level `method` and `id` fields of each JSON-RPC request object. Other protocol-level
validation, such as the `jsonrpc` version field or the shape of `params`, is left to the upstream. An empty method name
(`""`) is treated like any other method: it is forwarded in blocklist-only mode unless blocked, and rejected in
allowlist mode unless allowed.

## Production Deployment

The plugin cannot enforce read deadlines on the request body, and does not decompress request bodies. Configure
Traefik accordingly when it is directly exposed to untrusted clients.

### Timeouts

Configure `respondingTimeouts` on the entry point to bound slow clients (slow-loris). Traefik defaults to
`readTimeout: 60s` and `idleTimeout: 180s`; lower values are usually appropriate for JSON-RPC:

```yaml
# traefik.yml (static configuration)
entryPoints:
  websecure:
    address: ":443"
    transport:
      respondingTimeouts:
        readTimeout: "30s"
        writeTimeout: "30s"
        idleTimeout: "120s"
```

### Middleware Ordering

Place cheap rejections, such as rate limiting, IP allowlists, and authentication, before `jsonrpc-filter`.

The plugin does not decompress request bodies, so requests with a compressed body (e.g. `Content-Encoding: gzip`) fail
JSON parsing and are rejected as bad requests. If a middleware before `jsonrpc-filter` decompresses request bodies,
`maxBodyBytes` applies to the decompressed bytes, and that middleware must bound decompression itself.

### Sizing

Every inspected request body is buffered in memory, up to `maxBodyBytes`. Most JSON-RPC requests are well under 1 KiB,
so lowering `maxBodyBytes` (e.g. to 64-256 KiB) and `maxBatchSize` (e.g. to 10-50) bounds per-request memory and
upstream load. Set `restrictHTTPMethods: true` for endpoints that do not need to serve browser CORS preflight requests.

### Observability

The plugin does not produce logs or metrics. Use
Traefik [access logs](https://doc.traefik.io/traefik/observe/logs-and-access-logs/)
and [metrics](https://doc.traefik.io/traefik/observe/metrics/) to monitor rejected requests by status code.

## License

The contents of this repository are distributed under the terms of the MIT License, except where otherwise noted.
For more information, please refer to the [LICENSE](LICENSE) file.
