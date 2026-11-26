// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package traefik_jsonrpc_filter

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// recordHandler captures whether it was invoked and the forwarded body.
type recordHandler struct {
	called bool
	body   string
}

func (h *recordHandler) ServeHTTP(_ http.ResponseWriter, req *http.Request) {
	h.called = true
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		h.body = string(b)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "no methods configured",
			config:  &Config{},
			wantErr: true,
		},
		{
			name: "invalid blocked regex",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: "regex:"}},
			},
			wantErr: true,
		},
		{
			name:    "invalid allowed regex",
			config:  &Config{AllowedMethods: []string{"regex:[bad"}},
			wantErr: true,
		},
		{
			name: "unsupported blocked glob",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: "a*b*c"}},
			},
			wantErr: true,
		},
		{
			name: "block status code too low",
			config: &Config{
				BlockedMethods:  []BlockedMethod{{Pattern: "debug_*"}},
				BlockStatusCode: 200,
			},
			wantErr: true,
		},
		{
			name: "block status code too high",
			config: &Config{
				BlockedMethods:  []BlockedMethod{{Pattern: "debug_*"}},
				BlockStatusCode: 600,
			},
			wantErr: true,
		},
		{
			name: "bad request status code too low",
			config: &Config{
				BlockedMethods:       []BlockedMethod{{Pattern: "debug_*"}},
				BadRequestStatusCode: 200,
			},
			wantErr: true,
		},
		{
			name: "bad request status code too high",
			config: &Config{
				BlockedMethods:       []BlockedMethod{{Pattern: "debug_*"}},
				BadRequestStatusCode: 600,
			},
			wantErr: true,
		},
		{
			name: "negative max body bytes",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: "debug_*"}},
				MaxBodyBytes:   -1,
			},
			wantErr: true,
		},
		{
			name: "max int64 body bytes",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: "debug_*"}},
				MaxBodyBytes:   math.MaxInt64,
			},
			wantErr: true,
		},
		{
			name: "negative max batch size",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: "debug_*"}},
				MaxBatchSize:   -1,
			},
			wantErr: true,
		},
		{
			name: "empty blocked pattern",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: ""}},
				AllowedMethods: []string{"eth_*"},
			},
			wantErr: true,
		},
		{
			name: "whitespace padded blocked pattern",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: "eth_sendRawTransaction "}},
			},
			wantErr: true,
		},
		{
			name:    "empty allowed pattern",
			config:  &Config{AllowedMethods: []string{"eth_*", ""}},
			wantErr: true,
		},
		{
			name: "unencodable block error",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: "debug_*"}},
				BlockError:     &JSONRPCError{Data: map[any]any{"a": 1}},
			},
			wantErr: true,
		},
		{
			name: "unencodable bad request error data",
			config: &Config{
				BlockedMethods:  []BlockedMethod{{Pattern: "debug_*"}},
				BadRequestError: &JSONRPCError{Data: map[any]any{"a": 1}},
			},
			wantErr: true,
		},
		{
			name: "unencodable blocked method error data",
			config: &Config{
				BlockedMethods: []BlockedMethod{{
					Pattern: "debug_*",
					Error:   &JSONRPCError{Data: map[any]any{"a": 1}},
				}},
			},
			wantErr: true,
		},
		{
			name: "blocked method status code too low",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: "debug_*", StatusCode: 399}},
			},
			wantErr: true,
		},
		{
			name: "blocked method status code too high",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: "debug_*", StatusCode: 600}},
			},
			wantErr: true,
		},
		{
			name: "blocked method status code at bounds",
			config: &Config{
				BlockedMethods: []BlockedMethod{
					{Pattern: "debug_*", StatusCode: 400},
					{Pattern: "admin_*", StatusCode: 599},
				},
			},
			wantErr: false,
		},
		{
			name: "valid blocklist only",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: "debug_*"}},
			},
			wantErr: false,
		},
		{
			name: "valid blocklist with error",
			config: &Config{
				BlockedMethods: []BlockedMethod{{
					Pattern: "debug_*",
					Error: &JSONRPCError{
						Code:    -12345,
						Message: "error message",
					},
				}},
			},
			wantErr: false,
		},
		{
			name:    "valid allowlist only",
			config:  &Config{AllowedMethods: []string{"eth_*"}},
			wantErr: false,
		},
		{
			name: "valid block and allow",
			config: &Config{
				BlockedMethods: []BlockedMethod{
					{Pattern: "eth_sendRawTransaction"},
				},
				AllowedMethods: []string{"eth_*"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(t.Context(), http.NotFoundHandler(), tt.config, "test")
			if (err != nil) != tt.wantErr {
				t.Fatalf("New() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewDoesNotMutateConfig(t *testing.T) {
	t.Parallel()

	// newConfig returns a config with zero-value fields that New fills with
	// defaults, and partially populated JSON-RPC errors that New merges with
	// the default errors.
	newConfig := func() *Config {
		return &Config{
			BlockedMethods: []BlockedMethod{
				{Pattern: "debug_*", Error: &JSONRPCError{Message: "debug disabled"}},
				{Pattern: "admin_*"},
			},
			BlockError:             &JSONRPCError{Code: -32000},
			BadRequestError:        &JSONRPCError{Message: "bad"},
			PassthroughHTTPMethods: []string{"options"},
		}
	}

	cfg := newConfig()
	h, err := New(t.Context(), http.NotFoundHandler(), cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// reflect.DeepEqual follows pointers, so this also covers the
	// caller-owned *JSONRPCError values.
	if !reflect.DeepEqual(cfg, newConfig()) {
		t.Error("New mutated the caller's config or its JSON-RPC errors")
	}

	// Defaults still take effect in the running plugin.
	tests := []struct {
		body       string
		wantStatus int
		wantBody   string
	}{
		{
			body:       `{"jsonrpc":"2.0","method":"debug_trace","id":1}`,
			wantStatus: DefaultBlockStatusCode,
			wantBody:   `{"jsonrpc":"2.0","error":{"code":-32000,"message":"debug disabled"},"id":1}`,
		},
		{
			body:       `{"jsonrpc":"2.0","method":"admin_peers","id":2}`,
			wantStatus: DefaultBlockStatusCode,
			wantBody:   `{"jsonrpc":"2.0","error":{"code":-32000,"message":"method not allowed"},"id":2}`,
		},
		{
			body:       `{not json}`,
			wantStatus: DefaultBadRequestStatusCode,
			wantBody:   `{"jsonrpc":"2.0","error":{"code":-32600,"message":"bad"},"id":null}`,
		},
	}
	for _, tt := range tests {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/",
			strings.NewReader(tt.body))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tt.wantStatus {
			t.Errorf("%s: status = %d, want %d", tt.body, rr.Code, tt.wantStatus)
		}
		if got := strings.TrimSpace(rr.Body.String()); got != tt.wantBody {
			t.Errorf("%s: body = %s, want %s", tt.body, got, tt.wantBody)
		}
	}
}

func TestServeHTTP(t *testing.T) {
	t.Parallel()

	type request struct {
		httpMethod    string
		body          string
		nilBody       bool
		contentLength int64  // override Content-Length; 0 uses default from body
		contentType   string // override Content-Type; empty uses default
	}

	tests := []struct {
		name           string
		config         *Config
		req            request
		wantStatus     int
		wantAllow      string // Allow response header; empty asserts it is absent
		wantBodySubstr string // substring in response body
		wantNextCalled bool
		wantNextBody   string // body forwarded to next handler (only checked if wantNextCalled)
	}{
		// HTTP method handling
		{
			name:   "OPTIONS passthrough",
			config: &Config{AllowedMethods: []string{"eth_call"}},
			req: request{
				httpMethod: http.MethodOptions,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:   "OPTIONS passthrough with body rejected",
			config: &Config{AllowedMethods: []string{"eth_call"}},
			req: request{
				httpMethod: http.MethodOptions,
				body:       `{"jsonrpc":"2.0","method":"debug_traceTransaction","id":1}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: `"code":-32600`,
			wantNextCalled: false,
		},
		{
			name:   "OPTIONS passthrough with unknown-length body rejected",
			config: &Config{AllowedMethods: []string{"eth_call"}},
			req: request{
				httpMethod:    http.MethodOptions,
				body:          `{"jsonrpc":"2.0","method":"debug_traceTransaction","id":1}`,
				contentLength: -1, // e.g. Transfer-Encoding: chunked
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: `"code":-32600`,
			wantNextCalled: false,
		},
		{
			name: "custom passthrough GET with body rejected",
			config: &Config{
				AllowedMethods:         []string{"eth_call"},
				PassthroughHTTPMethods: []string{"GET"},
			},
			req: request{
				httpMethod: http.MethodGet,
				body:       `{"jsonrpc":"2.0","method":"debug_traceTransaction","id":1}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: `"code":-32600`,
			wantNextCalled: false,
		},
		{
			name:   "GET rejected",
			config: &Config{AllowedMethods: []string{"eth_call"}},
			req: request{
				httpMethod: http.MethodGet,
			},
			wantStatus:     http.StatusMethodNotAllowed,
			wantAllow:      "POST, OPTIONS",
			wantNextCalled: false,
		},
		{
			name: "Allow header deduplicates custom passthrough methods",
			config: &Config{
				AllowedMethods:         []string{"eth_call"},
				PassthroughHTTPMethods: []string{"get", "OPTIONS", "post", "GET", "options", "POST"},
			},
			req: request{
				httpMethod: http.MethodPut,
			},
			wantStatus:     http.StatusMethodNotAllowed,
			wantAllow:      "POST, GET, OPTIONS",
			wantNextCalled: false,
		},
		{
			name: "custom passthrough GET",
			config: &Config{
				AllowedMethods:         []string{"eth_call"},
				PassthroughHTTPMethods: []string{"GET", "OPTIONS"},
			},
			req: request{
				httpMethod: http.MethodGet,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name: "passthrough is case-insensitive",
			config: &Config{
				AllowedMethods:         []string{"eth_call"},
				PassthroughHTTPMethods: []string{"options"},
			},
			req: request{
				httpMethod: http.MethodOptions,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},

		// POST nil/empty body
		{
			name:   "nil body",
			config: &Config{AllowedMethods: []string{"eth_call"}},
			req: request{
				httpMethod: http.MethodPost,
				nilBody:    true,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},

		// Blocklist
		{
			name:   "blocklist exact block",
			config: &Config{BlockedMethods: []BlockedMethod{{Pattern: "debug_traceTransaction"}}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"debug_traceTransaction","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantBodySubstr: "-32601",
			wantNextCalled: false,
		},
		{
			name:   "blocklist exact allow",
			config: &Config{BlockedMethods: []BlockedMethod{{Pattern: "debug_traceTransaction"}}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
			wantNextBody:   `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
		},
		{
			name:   "blocklist prefix blocks",
			config: &Config{BlockedMethods: []BlockedMethod{{Pattern: "debug_*"}}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"debug_traceCall","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:   "blocklist prefix allows non-match",
			config: &Config{BlockedMethods: []BlockedMethod{{Pattern: "debug_*"}}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:   "blocklist suffix blocks",
			config: &Config{BlockedMethods: []BlockedMethod{{Pattern: "*_admin"}}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_admin","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:   "blocklist suffix allows non-match",
			config: &Config{BlockedMethods: []BlockedMethod{{Pattern: "*_admin"}}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:   "blocklist contains blocks",
			config: &Config{BlockedMethods: []BlockedMethod{{Pattern: "*debug*"}}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_debug_trace","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name: "blocklist regex blocks",
			config: &Config{BlockedMethods: []BlockedMethod{
				{Pattern: "regex:debug_.*"},
			}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"debug_traceBlock","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:   "blocklist regex auto-anchor prevents partial match",
			config: &Config{BlockedMethods: []BlockedMethod{{Pattern: "regex:debug"}}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"not_debug","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},

		// Allowlist
		{
			name:   "allowlist allows matching method",
			config: &Config{AllowedMethods: []string{"eth_call"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:   "allowlist blocks non-matching method",
			config: &Config{AllowedMethods: []string{"eth_call"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"debug_trace","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantBodySubstr: "-32601",
			wantNextCalled: false,
		},
		{
			name:   "allowlist prefix allows matching method",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_sendRawTransaction","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:   "allowlist prefix blocks non-matching method",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"debug_trace","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},

		// Combined block + allow (block takes precedence)
		{
			name: "block takes precedence over allow",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: "eth_sendRawTransaction"}},
				AllowedMethods: []string{"eth_*"},
			},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_sendRawTransaction","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name: "allowed method not in blocklist passes",
			config: &Config{
				BlockedMethods: []BlockedMethod{{Pattern: "eth_sendRawTransaction"}},
				AllowedMethods: []string{"eth_*"},
			},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},

		// Batch requests
		{
			name:   "batch all allowed",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1},{"jsonrpc":"2.0","method":"eth_blockNumber","id":2}]`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:   "batch one blocked",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1},{"jsonrpc":"2.0","method":"debug_trace","id":2}]`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:   "empty batch rejected",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `[]`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			name:   "batch exceeds max batch size",
			config: &Config{AllowedMethods: []string{"eth_*"}, MaxBatchSize: 2},
			req: request{
				httpMethod: http.MethodPost,
				body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1},{"jsonrpc":"2.0","method":"eth_call","id":2},{"jsonrpc":"2.0","method":"eth_call","id":3}]`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			name:   "batch at max batch size allowed",
			config: &Config{AllowedMethods: []string{"eth_*"}, MaxBatchSize: 2},
			req: request{
				httpMethod: http.MethodPost,
				body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1},{"jsonrpc":"2.0","method":"eth_call","id":2}]`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},

		// Malformed JSON -> 400
		{
			name:   "invalid JSON",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{not json`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			name:   "top-level string",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `"just a string"`,
			},
			wantStatus:     http.StatusBadRequest,
			wantNextCalled: false,
		},
		{
			name:   "missing method field",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","id":1}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			name:   "method value is number",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":42,"id":1}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantNextCalled: false,
		},
		{
			name:   "method value is object",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":{"nested":true},"id":1}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantNextCalled: false,
		},
		{
			name:   "batch element is not object",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `["not an object"]`,
			},
			wantStatus:     http.StatusBadRequest,
			wantNextCalled: false,
		},

		// Duplicate method field -> 400
		{
			name:   "duplicate method field",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","method":"debug_trace","id":1}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},

		// Keys are matched case-insensitively, like encoding/json does when
		// upstreams decode the request into a struct.
		{
			name:   "case-variant method key after method",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","Method":"debug_traceTransaction"}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			name:   "case-variant method key before method",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","METHOD":"debug_traceTransaction","method":"eth_chainId","id":1}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			name:   "unicode-escaped case-variant method key",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_chainId","\u004dethod":"debug_traceTransaction","id":1}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			name:   "case-variant method key alone is inspected",
			config: &Config{BlockedMethods: []BlockedMethod{{Pattern: "debug_*"}}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","mEtHoD":"debug_traceTransaction","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantBodySubstr: `"id":1`,
			wantNextCalled: false,
		},
		{
			name:   "case-variant method key in batch element",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1},{"jsonrpc":"2.0","method":"eth_call","Method":"debug_trace","id":2}]`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			name:   "case-variant id key duplicate",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","id":1,"ID":2,"method":"eth_call"}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},

		// Trailing content -> 400
		{
			name:   "trailing content after object",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}{"jsonrpc":"2.0","method":"debug_trace","id":2}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantNextCalled: false,
		},

		// Malformed JSON variants exercising specific evaluator branches
		{
			// Hits the "trailing content" error branch in evaluate
			// (well-formed object followed by malformed garbage).
			name:   "malformed trailing content after object",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}garbage`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			// Hits "read batch element" error in evaluateBatchElement.
			name:   "malformed batch element after valid one",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1}, bad]`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			// Hits "read \"method\" value" error in evaluateObject.
			name:   "truncated body after method key",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			// Hits "skip delim" error path in evaluateObject when method
			// value is a malformed compound (unclosed array).
			name:   "method value is malformed compound",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"method":[1`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			// Hits "read '}'" error path in evaluateObject when an
			// unclosed object lives inside a batch.
			name:   "batch element object unclosed",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `[{`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			// Hits "read ']'" error path in evaluate when a batch is
			// missing its closing bracket.
			name:   "batch missing closing bracket",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			// Hits the skipValue error path when a non-method field has a
			// malformed value.
			name:   "non-method field has malformed value",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"foo":invalid,"method":"eth_call"}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},

		{
			// Hits the readID error path (truncated body after id key).
			name:   "truncated body after id key",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"id":`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			// Hits the readID error path with a malformed array id.
			name:   "id is malformed compound (unclosed array)",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"id":[1,`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			// Hits the duplicate id field error path in evaluateObject.
			name:   "duplicate id field",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"id":1,"id":2,"method":"eth_call"}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},

		// Method name exceeding max -> 400
		{
			name:   "method name too long",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"` + strings.Repeat("a", 257) + `","id":1}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "-32600",
			wantNextCalled: false,
		},
		{
			name:   "method at max length allowed",
			config: &Config{AllowedMethods: []string{"*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"` + strings.Repeat("a", 256) + `","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},

		// Oversized body -> 400
		{
			name: "content-length exceeds max",
			config: &Config{
				AllowedMethods: []string{"eth_*"},
				MaxBodyBytes:   64,
			},
			req: request{
				httpMethod:    http.MethodPost,
				body:          `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
				contentLength: 65,
			},
			wantStatus:     http.StatusBadRequest,
			wantNextCalled: false,
		},
		{
			name: "actual body exceeds max despite content-length",
			config: &Config{
				AllowedMethods: []string{"eth_*"},
				MaxBodyBytes:   10,
			},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
			},
			wantStatus:     http.StatusBadRequest,
			wantNextCalled: false,
		},
		{
			// Content-Length under-reports body size, bypassing the early
			// req.ContentLength > maxBodyBytes check. The buf.Len check
			// after reading should still reject the oversized body.
			name: "buffered body exceeds max with under-reported content-length",
			config: &Config{
				AllowedMethods: []string{"eth_*"},
				MaxBodyBytes:   50,
			},
			req: request{
				httpMethod:    http.MethodPost,
				body:          `{"jsonrpc":"2.0","method":"eth_call","params":["` + strings.Repeat("a", 200) + `"],"id":1}`,
				contentLength: 1,
			},
			wantStatus:     http.StatusBadRequest,
			wantNextCalled: false,
		},
		{
			// Content-Length exceeds maxGrowHint (64 KiB); the buf.Grow hint
			// should be capped at maxGrowHint rather than allocated in full.
			name: "content-length exceeds grow hint cap",
			config: &Config{
				AllowedMethods: []string{"eth_*"},
				MaxBodyBytes:   1 << 20,
			},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","params":["` + strings.Repeat("a", 70<<10) + `"],"id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},

		// Custom block status code and body
		{
			name: "custom block status and body",
			config: &Config{
				BlockedMethods:  []BlockedMethod{{Pattern: "debug_*"}},
				BlockStatusCode: 429,
				BlockError: &JSONRPCError{
					Code:    1,
					Message: "blocked",
				},
			},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"debug_trace","id":1}`,
			},
			wantStatus:     429,
			wantBodySubstr: `{"jsonrpc":"2.0","error":{"code":1,"message":"blocked"},"id":1}`,
			wantNextCalled: false,
		},
		{
			name: "custom block error with data field",
			config: &Config{
				BlockedMethods:  []BlockedMethod{{Pattern: "debug_*"}},
				BlockStatusCode: 451,
				BlockError: &JSONRPCError{
					Code:    -1,
					Message: "policy",
					Data:    "see docs",
				},
			},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"debug_trace","id":1}`,
			},
			wantStatus:     451,
			wantBodySubstr: `"data":"see docs"`,
			wantNextCalled: false,
		},
		{
			name: "blocked method with error and status code",
			config: &Config{
				BlockedMethods: []BlockedMethod{{
					// Per RFC 2324, any attempt to brew coffee with a teapot
					// should result in the error code "418 I'm a teapot".
					Pattern:    "coffee_brew",
					StatusCode: http.StatusTeapot,
					Error: &JSONRPCError{
						Code:    http.StatusTeapot,
						Message: "I'm a teapot",
					},
				}},
			},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"coffee_brew","params":{"additions":["Whole-milk"]},"id":1}`,
			},
			wantStatus:     http.StatusTeapot,
			wantBodySubstr: `"code":418,"message":"I'm a teapot"`,
			wantNextCalled: false,
		},

		// Custom bad-request status code and body
		{
			name: "custom bad request status and body",
			config: &Config{
				AllowedMethods:       []string{"eth_*"},
				BadRequestStatusCode: 422,
				BadRequestError: &JSONRPCError{
					Code:    2,
					Message: "bad",
				},
			},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{not json}`,
			},
			wantStatus:     422,
			wantBodySubstr: `{"jsonrpc":"2.0","error":{"code":2,"message":"bad"},"id":null}`,
			wantNextCalled: false,
		},

		// Body forwarding integrity
		{
			name:   "body forwarded intact",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","params":["0x1",true],"id":99}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
			wantNextBody:   `{"jsonrpc":"2.0","method":"eth_call","params":["0x1",true],"id":99}`,
		},
		{
			name:   "batch body forwarded intact",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1}]`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
			wantNextBody:   `[{"jsonrpc":"2.0","method":"eth_call","id":1}]`,
		},

		// Method field not first key
		{
			name:   "method field after other keys",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","id":1,"params":[],"method":"eth_call"}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},

		// Nested params skipped correctly
		{
			name:   "deeply nested params skipped",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"params":{"a":{"b":{"c":[1,2,{"d":3}]}}},"method":"eth_call","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},

		// RestrictHTTPMethods mode
		{
			name: "RestrictHTTPMethods rejects OPTIONS",
			config: &Config{
				AllowedMethods:      []string{"eth_*"},
				RestrictHTTPMethods: true,
			},
			req: request{
				httpMethod: http.MethodOptions,
			},
			wantStatus:     http.StatusMethodNotAllowed,
			wantAllow:      "POST",
			wantNextCalled: false,
		},
		{
			name: "RestrictHTTPMethods rejects GET",
			config: &Config{
				AllowedMethods:      []string{"eth_*"},
				RestrictHTTPMethods: true,
			},
			req: request{
				httpMethod: http.MethodGet,
			},
			wantStatus:     http.StatusMethodNotAllowed,
			wantAllow:      "POST",
			wantNextCalled: false,
		},
		{
			name: "RestrictHTTPMethods allows POST",
			config: &Config{
				AllowedMethods:      []string{"eth_*"},
				RestrictHTTPMethods: true,
			},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name: "RestrictHTTPMethods ignores PassthroughHTTPMethods",
			config: &Config{
				AllowedMethods:         []string{"eth_*"},
				RestrictHTTPMethods:    true,
				PassthroughHTTPMethods: []string{"GET", "OPTIONS"},
			},
			req: request{
				httpMethod: http.MethodGet,
			},
			wantStatus:     http.StatusMethodNotAllowed,
			wantAllow:      "POST",
			wantNextCalled: false,
		},

		// Zero-value Config (no PassthroughHTTPMethods) falls back to
		// DefaultPassthroughHTTPMethods, so OPTIONS still passes through.
		{
			name:   "zero-value config defaults OPTIONS passthrough",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodOptions,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:   "zero-value config still rejects GET",
			config: &Config{AllowedMethods: []string{"eth_*"}},
			req: request{
				httpMethod: http.MethodGet,
			},
			wantStatus:     http.StatusMethodNotAllowed,
			wantAllow:      "POST, OPTIONS",
			wantNextCalled: false,
		},

		// Unicode escapes
		{
			name:   "unicode-escaped method key",
			config: &Config{BlockedMethods: []BlockedMethod{{Pattern: "debug_trace"}}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","\u006dethod":"debug_trace","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:   "unicode-escaped method value",
			config: &Config{BlockedMethods: []BlockedMethod{{Pattern: "debug_trace"}}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"debug_\u0074race","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},

		// Content-Type does not affect inspection
		{
			name:   "non-JSON content-type still inspected",
			config: &Config{BlockedMethods: []BlockedMethod{{Pattern: "debug_trace"}}},
			req: request{
				httpMethod:  http.MethodPost,
				body:        `{"jsonrpc":"2.0","method":"debug_trace","id":1}`,
				contentType: "text/plain",
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			nh := &recordHandler{}
			h, err := New(t.Context(), nh, tt.config, "test")
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			var body io.Reader
			if !tt.req.nilBody {
				body = strings.NewReader(tt.req.body)
			}
			req := httptest.NewRequestWithContext(t.Context(), tt.req.httpMethod, "/", body)

			if tt.req.contentLength != 0 {
				req.ContentLength = tt.req.contentLength
			}
			if tt.req.contentType != "" {
				req.Header.Set("Content-Type", tt.req.contentType)
			}

			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body = %s",
					rr.Code, tt.wantStatus, rr.Body.String())
			}
			if got := rr.Header().Get("Allow"); got != tt.wantAllow {
				t.Errorf("Allow = %q, want %q", got, tt.wantAllow)
			}
			if tt.wantBodySubstr != "" && !strings.Contains(rr.Body.String(), tt.wantBodySubstr) {
				t.Errorf("body = %q, want substring %q",
					rr.Body.String(), tt.wantBodySubstr)
			}
			if nh.called != tt.wantNextCalled {
				t.Errorf("next.called = %v, want %v",
					nh.called, tt.wantNextCalled)
			}
			if tt.wantNextCalled && tt.wantNextBody != "" && nh.body != tt.wantNextBody {
				t.Errorf("next.body = %q, want %q", nh.body, tt.wantNextBody)
			}
		})
	}
}

func TestCreateConfig(t *testing.T) {
	t.Parallel()
	cfg := CreateConfig()
	if cfg == nil {
		t.Fatal("CreateConfig returned nil")
	}
	if cfg.MaxBodyBytes != DefaultMaxBodyBytes {
		t.Errorf("MaxBodyBytes = %d, want %d",
			cfg.MaxBodyBytes, DefaultMaxBodyBytes)
	}
	if cfg.BlockStatusCode != DefaultBlockStatusCode {
		t.Errorf("BlockStatusCode = %d, want %d",
			cfg.BlockStatusCode, DefaultBlockStatusCode)
	}
	if cfg.BadRequestStatusCode != DefaultBadRequestStatusCode {
		t.Errorf("BadRequestStatusCode = %d, want %d",
			cfg.BadRequestStatusCode, DefaultBadRequestStatusCode)
	}
	if cfg.MaxBatchSize != DefaultMaxBatchSize {
		t.Errorf("MaxBatchSize = %d, want %d",
			cfg.MaxBatchSize, DefaultMaxBatchSize)
	}
	if !reflect.DeepEqual(cfg.BlockError, defaultBlockError) {
		t.Errorf("BlockError = %#+v, want %#+v",
			cfg.BlockError, defaultBlockError)
	}
	if !reflect.DeepEqual(cfg.BadRequestError, defaultBadReqError) {
		t.Errorf("BadRequestError = %#+v, want %#+v",
			cfg.BadRequestError, defaultBadReqError)
	}
	if len(cfg.PassthroughHTTPMethods) != len(DefaultPassthroughHTTPMethods) {
		t.Errorf("PassthroughHTTPMethods len = %d, want %d",
			len(cfg.PassthroughHTTPMethods),
			len(DefaultPassthroughHTTPMethods))
	}
}

func TestCreateConfigNotShared(t *testing.T) {
	t.Parallel()
	// Snapshot as JSON, which deep-copies any values shared with the defaults.
	want, err := json.Marshal(CreateConfig())
	if err != nil {
		t.Fatal(err)
	}

	err = json.Unmarshal([]byte(`{
		"blockError": {"code": -1, "message": "first"},
		"badRequestError": {"code": -2, "message": "first"},
		"passthroughHTTPMethods": ["GET"]
	}`), CreateConfig())
	if err != nil {
		t.Fatal(err)
	}

	got, err := json.Marshal(CreateConfig())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("CreateConfig() = %s, want %s", got, want)
	}
}

func TestServeHTTPNilBody(t *testing.T) {
	t.Parallel()
	cfg := &Config{AllowedMethods: []string{"eth_call"}}
	nh := &recordHandler{}
	h, err := New(t.Context(), nh, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(),
		http.MethodPost, "/", nil)
	req.Body = nil

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if nh.called {
		t.Error("next handler should not be called")
	}
}

func TestServeHTTPResponseID(t *testing.T) {
	t.Parallel()

	cfg := &Config{BlockedMethods: []BlockedMethod{{Pattern: "debug_*"}}}
	tests := []struct {
		name       string
		body       string
		wantIDJSON string // expected "id":<value> substring in response body
	}{
		{
			name:       "numeric id echoed",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":42}`,
			wantIDJSON: `"id":42`,
		},
		{
			name:       "negative numeric id echoed",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":-7}`,
			wantIDJSON: `"id":-7`,
		},
		{
			name:       "fractional numeric id echoed",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":1.5}`,
			wantIDJSON: `"id":1.5`,
		},
		{
			name:       "very large integer id preserved as text",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":99999999999999999999}`,
			wantIDJSON: `"id":99999999999999999999`,
		},
		{
			name:       "string id echoed",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":"req-1"}`,
			wantIDJSON: `"id":"req-1"`,
		},
		{
			name:       "string id with escapes re-encoded safely",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":"a\"b"}`,
			wantIDJSON: `"id":"a\"b"`,
		},
		{
			name:       "null id echoed",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":null}`,
			wantIDJSON: `"id":null`,
		},
		{
			name:       "missing id defaults to null",
			body:       `{"jsonrpc":"2.0","method":"debug_x"}`,
			wantIDJSON: `"id":null`,
		},
		{
			name:       "id surrounded by whitespace echoed",
			body:       "{\"jsonrpc\":\"2.0\",\"method\":\"debug_x\",\"id\" : \n\t 7 }",
			wantIDJSON: `"id":7`,
		},
		{
			name:       "case-variant id key echoed",
			body:       `{"jsonrpc":"2.0","method":"debug_x","Id":7}`,
			wantIDJSON: `"id":7`,
		},
		{
			name:       "id appears before method",
			body:       `{"id":7,"jsonrpc":"2.0","method":"debug_x"}`,
			wantIDJSON: `"id":7`,
		},
		{
			name:       "id appears after method (late capture)",
			body:       `{"jsonrpc":"2.0","method":"debug_x","params":[],"id":9}`,
			wantIDJSON: `"id":9`,
		},
		{
			name:       "boolean id dropped to null",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":true}`,
			wantIDJSON: `"id":null`,
		},
		{
			name:       "object id dropped to null",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":{"x":1}}`,
			wantIDJSON: `"id":null`,
		},
		{
			name:       "array id dropped to null",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":[1,2]}`,
			wantIDJSON: `"id":null`,
		},
		{
			name:       "oversized string id dropped to null",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":"` + strings.Repeat("a", 257) + `"}`,
			wantIDJSON: `"id":null`,
		},
		{
			name:       "string id at max length preserved",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":"` + strings.Repeat("a", 256) + `"}`,
			wantIDJSON: `"id":"` + strings.Repeat("a", 256) + `"`,
		},
		{
			// Raw literal at maxRawIDBytes, decoding to exactly maxIDBytes.
			name:       "escaped string id at max decoded length preserved",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":"` + strings.Repeat(`\u0061`, 256) + `"}`,
			wantIDJSON: `"id":"` + strings.Repeat("a", 256) + `"`,
		},
		{
			name:       "escaped string id over max decoded length dropped to null",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":"` + strings.Repeat(`\u0061`, 257) + `"}`,
			wantIDJSON: `"id":null`,
		},
		{
			name:       "string id with invalid UTF-8 re-encoded",
			body:       "{\"jsonrpc\":\"2.0\",\"method\":\"debug_x\",\"id\":\"a\xffb\"}",
			wantIDJSON: "\"id\":\"a\uFFFDb\"",
		},
		{
			name:       "string id with HTML characters escaped",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":"<a>&"}`,
			wantIDJSON: `"id":"\u003ca\u003e\u0026"`,
		},
		{
			name:       "oversized numeric id dropped to null",
			body:       `{"jsonrpc":"2.0","method":"debug_x","id":` + strings.Repeat("9", 257) + `}`,
			wantIDJSON: `"id":null`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nh := &recordHandler{}
			h, err := New(t.Context(), nh, cfg, "test")
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			req := httptest.NewRequestWithContext(t.Context(),
				http.MethodPost, "/", strings.NewReader(tt.body))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body = %s",
					rr.Code, http.StatusForbidden, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tt.wantIDJSON) {
				t.Errorf("body = %q, want substring %q",
					rr.Body.String(), tt.wantIDJSON)
			}
			if nh.called {
				t.Error("next handler should not be called")
			}
		})
	}
}

func TestServeHTTPResponseIDBatch(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		AllowedMethods: []string{"eth_*"},
		BlockedMethods: []BlockedMethod{{Pattern: "debug_*"}},
	}
	tests := []struct {
		name       string
		body       string
		wantIDJSON string
	}{
		{
			name:       "first element blocked echoes its id",
			body:       `[{"jsonrpc":"2.0","method":"debug_x","id":1},{"jsonrpc":"2.0","method":"eth_call","id":2}]`,
			wantIDJSON: `"id":1`,
		},
		{
			name:       "second element blocked echoes its id",
			body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1},{"jsonrpc":"2.0","method":"debug_x","id":2}]`,
			wantIDJSON: `"id":2`,
		},
		{
			name:       "blocked element with string id",
			body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1},{"jsonrpc":"2.0","method":"debug_x","id":"abc"}]`,
			wantIDJSON: `"id":"abc"`,
		},
		{
			name:       "blocked element with no id",
			body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1},{"jsonrpc":"2.0","method":"debug_x"}]`,
			wantIDJSON: `"id":null`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nh := &recordHandler{}
			h, err := New(t.Context(), nh, cfg, "test")
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			req := httptest.NewRequestWithContext(t.Context(),
				http.MethodPost, "/", strings.NewReader(tt.body))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body = %s",
					rr.Code, http.StatusForbidden, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tt.wantIDJSON) {
				t.Errorf("body = %q, want substring %q",
					rr.Body.String(), tt.wantIDJSON)
			}
		})
	}
}

func TestServeHTTPBadRequestIDNull(t *testing.T) {
	t.Parallel()

	cfg := &Config{AllowedMethods: []string{"eth_*"}}
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed JSON with id", body: `{"id":5,"method":}`},
		{name: "duplicate id field", body: `{"id":1,"id":2,"method":"eth_call"}`},
		{name: "missing method with id", body: `{"id":99,"jsonrpc":"2.0"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nh := &recordHandler{}
			h, err := New(t.Context(), nh, cfg, "test")
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			req := httptest.NewRequestWithContext(t.Context(),
				http.MethodPost, "/", strings.NewReader(tt.body))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
			}
			if !strings.Contains(rr.Body.String(), `"id":null`) {
				t.Errorf("body = %q, want substring %q",
					rr.Body.String(), `"id":null`)
			}
		})
	}
}

// discardResponseWriter is a minimal http.ResponseWriter that records the
// http header, and discards data written.
type discardResponseWriter struct {
	header http.Header
	code   int
}

func newDiscardResponseWriter() *discardResponseWriter {
	return &discardResponseWriter{header: make(http.Header, 2)}
}

func (w *discardResponseWriter) Header() http.Header {
	return w.header
}

func (w *discardResponseWriter) WriteHeader(code int) {
	w.code = code
}

func (w *discardResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (w *discardResponseWriter) reset() {
	clear(w.header)
	w.code = 0
}

// nopHandler is the downstream handler that the plugin forwards to.
var nopHandler = http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
})

func newBenchPlugin(b *testing.B, cfg *Config) http.Handler {
	b.Helper()
	h, err := New(b.Context(), nopHandler, cfg, "bench")
	if err != nil {
		b.Fatal(err)
	}
	return h
}

// reqTemplate is reused across iterations; only Body is swapped per call.
var reqTemplate = &http.Request{
	Method: http.MethodPost,
	URL:    &url.URL{Path: "/"},
	Proto:  "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	Header: http.Header{"Content-Type": []string{"application/json"}},
	Host:   "localhost",
}

func benchServeHTTP(b *testing.B, h http.Handler, body string, wantStatus int) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		rw := newDiscardResponseWriter()
		served := false
		for pb.Next() {
			rw.reset()
			req := *reqTemplate
			req.Body = io.NopCloser(strings.NewReader(body))
			req.ContentLength = int64(len(body))
			h.ServeHTTP(rw, &req)
			served = true
		}
		if served && rw.code != wantStatus {
			b.Errorf("status = %d, want %d", rw.code, wantStatus)
		}
	})
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "req/s")
}

var (
	singleSmall = `{"jsonrpc":"2.0","method":"eth_call","id":1}`
	singleLarge = `{"jsonrpc":"2.0","method":"eth_call","params":["` + strings.Repeat("x", 4096) + `"],"id":1}`
)

func BenchmarkAllowed(b *testing.B) {
	h := newBenchPlugin(b, &Config{
		BlockedMethods: []BlockedMethod{{Pattern: "eth_sendRawTransaction"}},
		AllowedMethods: []string{"eth_*"},
	})
	benchServeHTTP(b, h, singleSmall, http.StatusOK)
}

func BenchmarkRejected(b *testing.B) {
	h := newBenchPlugin(b, &Config{BlockedMethods: []BlockedMethod{{Pattern: "eth_call"}}})
	benchServeHTTP(b, h, singleSmall, http.StatusForbidden)
}

func BenchmarkLargeBody(b *testing.B) {
	h := newBenchPlugin(b, &Config{AllowedMethods: []string{"eth_*"}})
	benchServeHTTP(b, h, singleLarge, http.StatusOK)
}

func BenchmarkMethodFieldLast(b *testing.B) {
	h := newBenchPlugin(b, &Config{AllowedMethods: []string{"eth_*"}})
	body := `{"jsonrpc":"2.0","id":1,"params":["0x1","0x2","0x3"],"method":"eth_call"}`
	benchServeHTTP(b, h, body, http.StatusOK)
}

func BenchmarkBatch(b *testing.B) {
	for _, size := range []int{1, 5, 10, 50} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			h := newBenchPlugin(b, &Config{AllowedMethods: []string{"eth_*"}})
			benchServeHTTP(b, h, buildBatch(size), http.StatusOK)
		})
	}
}

func buildBatch(n int) string {
	var b strings.Builder
	b.WriteByte('[')
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"jsonrpc":"2.0","method":"eth_call","id":%d}`, i)
	}
	b.WriteByte(']')
	return b.String()
}

func BenchmarkPassthrough(b *testing.B) {
	h := newBenchPlugin(b, &Config{AllowedMethods: []string{"eth_*"}})
	optReq := &http.Request{
		Method: http.MethodOptions,
		URL:    &url.URL{Path: "/"},
		Proto:  "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: make(http.Header),
		Host:   "localhost",
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rw := newDiscardResponseWriter()
		served := false
		for pb.Next() {
			rw.reset()
			h.ServeHTTP(rw, optReq)
			served = true
		}
		if served && rw.code != http.StatusOK {
			b.Errorf("status = %d, want %d", rw.code, http.StatusOK)
		}
	})
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "req/s")
}

// Integration tests against a live Traefik instance.
//
// Set TRAEFIK_INTEGRATION_URL to the base URL of a running Traefik with the
// plugin configured per example/dynamic.yml:
//
//	blockedMethods: ["debug_*", "admin_*"]
//	allowedMethods: ["eth_*", "net_*", "web3_*"]
//	maxBatchSize:   50
//
// Example:
//
//	cd example && docker compose up -d
//	TRAEFIK_INTEGRATION_URL=http://localhost:3000 go test -v -run Integration
//	TRAEFIK_INTEGRATION_URL=http://localhost:3000 go test -run Integration -bench BenchmarkIntegration

func integrationURL(t testing.TB) string {
	t.Helper()
	u := os.Getenv("TRAEFIK_INTEGRATION_URL")
	if u == "" {
		t.Skip("TRAEFIK_INTEGRATION_URL not set; skipping integration tests")
	}
	return u
}

func TestIntegration(t *testing.T) {
	t.Parallel()
	base := integrationURL(t)
	client := &http.Client{Timeout: 10 * time.Second}

	tests := []struct {
		name       string
		httpMethod string
		body       string
		wantStatus int
		wantBody   string // substring
	}{
		// Allowed methods
		{
			name:       "allowed/eth_call",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "allowed/eth_blockNumber",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"eth_blockNumber","id":2}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "allowed/net_version",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"net_version","id":3}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "allowed/web3_clientVersion",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"web3_clientVersion","id":4}`,
			wantStatus: http.StatusOK,
		},

		// Blocked methods
		{
			name:       "blocked/debug_traceTransaction",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"debug_traceTransaction","id":1}`,
			wantStatus: http.StatusForbidden,
			wantBody:   "-32601",
		},
		{
			name:       "blocked/debug_traceCall",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"debug_traceCall","id":1}`,
			wantStatus: http.StatusForbidden,
			wantBody:   "-32601",
		},
		{
			name:       "blocked/admin_peers",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"admin_peers","id":1}`,
			wantStatus: http.StatusForbidden,
			wantBody:   "-32601",
		},
		{
			name:       "blocked/admin_nodeInfo",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"admin_nodeInfo","id":1}`,
			wantStatus: http.StatusForbidden,
			wantBody:   "-32601",
		},

		// Not in allowlist
		{
			name:       "not_allowed/unknown_method",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"unknown_method","id":1}`,
			wantStatus: http.StatusForbidden,
			wantBody:   "-32601",
		},
		{
			name:       "not_allowed/foo_bar",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"foo_bar","id":1}`,
			wantStatus: http.StatusForbidden,
			wantBody:   "-32601",
		},

		// Batch requests
		{
			name:       "batch/all_allowed",
			httpMethod: http.MethodPost,
			body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1},{"jsonrpc":"2.0","method":"net_version","id":2}]`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "batch/one_blocked",
			httpMethod: http.MethodPost,
			body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1},{"jsonrpc":"2.0","method":"debug_trace","id":2}]`,
			wantStatus: http.StatusForbidden,
			wantBody:   "-32601",
		},
		{
			name:       "batch/single_element",
			httpMethod: http.MethodPost,
			body:       `[{"jsonrpc":"2.0","method":"eth_call","id":1}]`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "batch/at_limit_50",
			httpMethod: http.MethodPost,
			body:       buildBatch(50),
			wantStatus: http.StatusOK,
		},
		{
			name:       "batch/over_limit_51",
			httpMethod: http.MethodPost,
			body:       buildBatch(51),
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},

		// Invalid requests
		{
			name:       "invalid/empty_body",
			httpMethod: http.MethodPost,
			body:       "",
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},
		{
			name:       "invalid/malformed_json",
			httpMethod: http.MethodPost,
			body:       `{not json}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},
		{
			name:       "invalid/missing_method",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","id":1}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},
		{
			name:       "invalid/method_not_string",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":123,"id":1}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},
		{
			name:       "invalid/empty_batch",
			httpMethod: http.MethodPost,
			body:       `[]`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},
		{
			name:       "invalid/batch_element_not_object",
			httpMethod: http.MethodPost,
			body:       `["not an object"]`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},
		{
			name:       "invalid/trailing_content",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}{"extra":true}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},
		{
			name:       "invalid/case_variant_method_key",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","Method":"debug_traceTransaction"}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},
		{
			name:       "invalid/duplicate_method",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"eth_call","method":"eth_call","id":1}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},
		{
			name:       "invalid/bare_string",
			httpMethod: http.MethodPost,
			body:       `"just a string"`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},
		{
			name:       "invalid/bare_number",
			httpMethod: http.MethodPost,
			body:       `42`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},

		// HTTP method handling
		{
			name:       "http/GET_rejected",
			httpMethod: http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "http/PUT_rejected",
			httpMethod: http.MethodPut,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "http/DELETE_rejected",
			httpMethod: http.MethodDelete,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "http/OPTIONS_passthrough",
			httpMethod: http.MethodOptions,
			wantStatus: http.StatusOK,
		},
		{
			name:       "http/OPTIONS_with_body_rejected",
			httpMethod: http.MethodOptions,
			body:       `{"jsonrpc":"2.0","method":"debug_traceTransaction","id":1}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "-32600",
		},

		// Edge cases
		{
			name:       "edge/method_field_last",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","id":1,"params":["0x1"],"method":"eth_call"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "edge/extra_fields",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"eth_call","id":1,"params":[],"extra":"data"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "edge/nested_params",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"eth_call","id":1,"params":[{"to":"0xabc","data":"0x123"},true,null,42]}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "edge/large_params",
			httpMethod: http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"eth_call","params":["` + strings.Repeat("a", 8192) + `"],"id":1}`,
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req, err := http.NewRequestWithContext(t.Context(), tt.httpMethod, base+"/", body)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d; body = %s",
					resp.StatusCode, tt.wantStatus, string(respBody))
			}
			if tt.wantBody != "" && !strings.Contains(string(respBody), tt.wantBody) {
				t.Errorf("body = %q, want substring %q",
					string(respBody), tt.wantBody)
			}
		})
	}
}

func benchIntegration(b *testing.B, base, method, body string) {
	b.Helper()
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{MaxIdleConnsPerHost: 64},
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var bodyReader io.Reader
			if body != "" {
				bodyReader = strings.NewReader(body)
			}
			req, _ := http.NewRequestWithContext(b.Context(), method, base+"/", bodyReader)
			if bodyReader != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := client.Do(req)
			if err != nil {
				b.Errorf("request failed: %v", err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	})
}

func BenchmarkIntegrationAllowed(b *testing.B) {
	base := integrationURL(b)
	benchIntegration(b, base, http.MethodPost, `{"jsonrpc":"2.0","method":"eth_call","id":1}`)
}

func BenchmarkIntegrationBlocked(b *testing.B) {
	base := integrationURL(b)
	benchIntegration(b, base, http.MethodPost, `{"jsonrpc":"2.0","method":"debug_traceTransaction","id":1}`)
}

func BenchmarkIntegrationBatch(b *testing.B) {
	base := integrationURL(b)
	for _, size := range []int{1, 5, 10, 50} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			benchIntegration(b, base, http.MethodPost, buildBatch(size))
		})
	}
}

func BenchmarkIntegrationPassthrough(b *testing.B) {
	base := integrationURL(b)
	benchIntegration(b, base, http.MethodOptions, "")
}

func BenchmarkIntegrationThroughput(b *testing.B) {
	base := integrationURL(b)
	body := `{"jsonrpc":"2.0","method":"eth_call","id":1}`
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{MaxIdleConnsPerHost: 128},
	}

	var ops atomic.Int64
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequestWithContext(b.Context(),
				http.MethodPost, base+"/", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				b.Errorf("request failed: %v", err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b.Errorf("unexpected status: %d", resp.StatusCode)
			}
			ops.Add(1)
		}
	})
	elapsed := time.Since(start)
	b.ReportMetric(float64(ops.Load())/elapsed.Seconds(), "req/s")
}
