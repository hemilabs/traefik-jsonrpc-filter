# traefik-jsonrpc-filter

[![Go Reference](https://pkg.go.dev/badge/github.com/hemilabs/traefik-jsonrpc-filter.svg)](https://pkg.go.dev/github.com/hemilabs/traefik-jsonrpc-filter)
[![Go Report Card](https://goreportcard.com/badge/github.com/hemilabs/traefik-jsonrpc-filter)](https://goreportcard.com/report/github.com/hemilabs/traefik-jsonrpc-filter)
[![MIT License](https://img.shields.io/badge/license-MIT-ff6c15)](LICENSE)

A [Traefik](https://traefik.io) middleware plugin that filters [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
requests by method name.

- **Block or allow methods.** Reject specific methods, or permit only known-good methods, or combine both.
- **Pattern matching.** Use exact match, `prefix*`, `*suffix`, `*contains*` or `regex:<expr>`.
- **Batch support.** Inspects every element of a JSON-RPC batch array.
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

| Option                   | Type       | Default                                                                              | Description                                                                  |
|--------------------------|------------|--------------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| `blockedMethods`         | `[]string` | —                                                                                    | Patterns to reject (evaluated first)                                         |
| `allowedMethods`         | `[]string` | —                                                                                    | Patterns to permit (evaluated after blocked)                                 |
| `maxBodyBytes`           | `int64`    | `1048576` (1 MiB)                                                                    | Max request body size in bytes                                               |
| `maxBatchSize`           | `int`      | `100`                                                                                | Max elements in a JSON-RPC batch array                                       |
| `blockStatusCode`        | `int`      | `403`                                                                                | HTTP status code for rejected requests (4xx/5xx)                             |
| `blockResponseBody`      | `string`   | `{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not allowed"},"id":null}` | JSON-RPC error body for rejected requests                                    |
| `restrictMethods`        | `bool`     | `false`                                                                              | Reject all non-POST requests with HTTP 405                                   |
| `passthroughHTTPMethods` | `[]string` | `["OPTIONS"]`                                                                        | HTTP methods that bypass inspection (ignored when `restrictMethods` is true) |

At least one of `blockedMethods` or `allowedMethods` must be configured.

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
