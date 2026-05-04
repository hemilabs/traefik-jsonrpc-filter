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
- **Fail closed.** Malformed JSON requests, missing `method` fields, oversized bodies, and deeply nested payloads are
  rejected.

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

### `BlockedMethod`

Each entry in `blockedMethods` is an object:

| Field     | Type           | Description                                                                       |
|-----------|----------------|-----------------------------------------------------------------------------------|
| `pattern` | `string`       | Pattern to match (see [Pattern Matching](#pattern-matching)).                     |
| `error`   | `JSONRPCError` | Optional per-method JSON-RPC error override. Falls back to `blockError` if unset. |

### `JSONRPCError`

A [JSON-RPC 2.0 error object](https://www.jsonrpc.org/specification#error_object).

| Field     | Type     | Default                                      | Description               |
|-----------|----------|----------------------------------------------|---------------------------|
| `code`    | `int`    | `-32601` (block) / `-32600` (bad)            | JSON-RPC error code.      |
| `message` | `string` | `"method not allowed"` / `"invalid request"` | Short error description.  |
| `data`    | `any`    | -                                            | Optional additional data. |

The response body sent to clients has the shape:

```json
{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not allowed"},"id":1}
```

## Batch Requests

Batches are inspected element-by-element. The plugin operates **fail-closed**: if any element matches a blocked
pattern (or, in allowlist mode, matches no allowed pattern), the entire batch is rejected.

Notes:

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

> **Note:** Regex patterns are automatically anchored with `^` and `$` to
> prevent accidental partial matches.

## License

The contents of this repository are distributed under the terms of the MIT License, except where otherwise noted.
For more information, please refer to the [LICENSE](LICENSE) file.
