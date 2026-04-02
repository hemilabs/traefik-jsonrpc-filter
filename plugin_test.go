// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package traefik_jsonrpc_filter

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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
			name:    "invalid blocked regex",
			config:  &Config{BlockedMethods: []string{"regex:"}},
			wantErr: true,
		},
		{
			name:    "invalid allowed regex",
			config:  &Config{AllowedMethods: []string{"regex:[bad"}},
			wantErr: true,
		},
		{
			name:    "unsupported blocked glob",
			config:  &Config{BlockedMethods: []string{"a*b*c"}},
			wantErr: true,
		},
		{
			name:    "block status code too low",
			config:  &Config{BlockedMethods: []string{"debug_*"}, BlockStatusCode: 200},
			wantErr: true,
		},
		{
			name:    "block status code too high",
			config:  &Config{BlockedMethods: []string{"debug_*"}, BlockStatusCode: 600},
			wantErr: true,
		},
		{
			name:    "valid blocklist only",
			config:  &Config{BlockedMethods: []string{"debug_*"}},
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
				BlockedMethods: []string{"eth_sendRawTransaction"},
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
			name:   "GET rejected",
			config: &Config{AllowedMethods: []string{"eth_call"}},
			req: request{
				httpMethod: http.MethodGet,
			},
			wantStatus:     http.StatusMethodNotAllowed,
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
			config: &Config{BlockedMethods: []string{"debug_traceTransaction"}},
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
			config: &Config{BlockedMethods: []string{"debug_traceTransaction"}},
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
			config: &Config{BlockedMethods: []string{"debug_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"debug_traceCall","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:   "blocklist prefix allows non-match",
			config: &Config{BlockedMethods: []string{"debug_*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:   "blocklist suffix blocks",
			config: &Config{BlockedMethods: []string{"*_admin"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_admin","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:   "blocklist suffix allows non-match",
			config: &Config{BlockedMethods: []string{"*_admin"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:   "blocklist contains blocks",
			config: &Config{BlockedMethods: []string{"*debug*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_debug_trace","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:   "blocklist regex blocks",
			config: &Config{BlockedMethods: []string{"regex:debug_.*"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"debug_traceBlock","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:   "blocklist regex auto-anchor prevents partial match",
			config: &Config{BlockedMethods: []string{"regex:debug"}},
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
				BlockedMethods: []string{"eth_sendRawTransaction"},
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
				BlockedMethods: []string{"eth_sendRawTransaction"},
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

		// Custom block status code and body
		{
			name: "custom block status and body",
			config: &Config{
				BlockedMethods:    []string{"debug_*"},
				BlockStatusCode:   429,
				BlockResponseBody: `{"error":"blocked"}`,
			},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"debug_trace","id":1}`,
			},
			wantStatus:     429,
			wantBodySubstr: `{"error":"blocked"}`,
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

		// RestrictMethods mode
		{
			name: "RestrictMethods rejects OPTIONS",
			config: &Config{
				AllowedMethods:  []string{"eth_*"},
				RestrictMethods: true,
			},
			req: request{
				httpMethod: http.MethodOptions,
			},
			wantStatus:     http.StatusMethodNotAllowed,
			wantNextCalled: false,
		},
		{
			name: "RestrictMethods rejects GET",
			config: &Config{
				AllowedMethods:  []string{"eth_*"},
				RestrictMethods: true,
			},
			req: request{
				httpMethod: http.MethodGet,
			},
			wantStatus:     http.StatusMethodNotAllowed,
			wantNextCalled: false,
		},
		{
			name: "RestrictMethods allows POST",
			config: &Config{
				AllowedMethods:  []string{"eth_*"},
				RestrictMethods: true,
			},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","method":"eth_call","id":1}`,
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name: "RestrictMethods ignores PassthroughHTTPMethods",
			config: &Config{
				AllowedMethods:         []string{"eth_*"},
				RestrictMethods:        true,
				PassthroughHTTPMethods: []string{"GET", "OPTIONS"},
			},
			req: request{
				httpMethod: http.MethodGet,
			},
			wantStatus:     http.StatusMethodNotAllowed,
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
			wantNextCalled: false,
		},

		// Unicode escapes
		{
			name:   "unicode-escaped method key",
			config: &Config{BlockedMethods: []string{"debug_trace"}},
			req: request{
				httpMethod: http.MethodPost,
				body:       `{"jsonrpc":"2.0","\u006dethod":"debug_trace","id":1}`,
			},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:   "unicode-escaped method value",
			config: &Config{BlockedMethods: []string{"debug_trace"}},
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
			config: &Config{BlockedMethods: []string{"debug_trace"}},
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

			if tt.req.contentLength > 0 {
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

func TestServeHTTPDeepNesting(t *testing.T) {
	t.Parallel()

	cfg := &Config{AllowedMethods: []string{"eth_*"}}
	nh := &recordHandler{}
	h, err := New(t.Context(), nh, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Build JSON with nesting deeper than maxNestDepth inside a skipped value.
	// {"params": [[[[...depth 70...]]], "method":"eth_call","id":1}
	var b strings.Builder
	b.WriteString(`{"params":`)
	depth := maxNestDepth + 10
	for range depth {
		b.WriteByte('[')
	}
	b.WriteString("1")
	for range depth {
		b.WriteByte(']')
	}
	b.WriteString(`,"method":"eth_call","id":1}`)

	rr := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(),
		http.MethodPost, "/", strings.NewReader(b.String()))
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("deep nesting: status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if nh.called {
		t.Error("deep nesting: next handler should not be called")
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

func benchServeHTTP(b *testing.B, h http.Handler, body string) {
	b.Helper()
	bodyBytes := []byte(body)
	rw := newDiscardResponseWriter()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rw.reset()
			req := *reqTemplate
			req.Body = io.NopCloser(strings.NewReader(body))
			req.ContentLength = int64(len(bodyBytes))
			h.ServeHTTP(rw, &req)
		}
	})
}

var (
	singleSmall = `{"jsonrpc":"2.0","method":"eth_call","id":1}`
	singleLarge = `{"jsonrpc":"2.0","method":"eth_call","params":["` + strings.Repeat("x", 4096) + `"],"id":1}`
)

func BenchmarkExactMatcher(b *testing.B) {
	h := newBenchPlugin(b, &Config{AllowedMethods: []string{"eth_call"}})
	benchServeHTTP(b, h, singleSmall)
}

func BenchmarkPrefixMatcher(b *testing.B) {
	h := newBenchPlugin(b, &Config{AllowedMethods: []string{"eth_*"}})
	benchServeHTTP(b, h, singleSmall)
}

func BenchmarkSuffixMatcher(b *testing.B) {
	h := newBenchPlugin(b, &Config{AllowedMethods: []string{"*_call"}})
	benchServeHTTP(b, h, singleSmall)
}

func BenchmarkContainsMatcher(b *testing.B) {
	h := newBenchPlugin(b, &Config{AllowedMethods: []string{"*call*"}})
	benchServeHTTP(b, h, singleSmall)
}

func BenchmarkRegexMatcher(b *testing.B) {
	h := newBenchPlugin(b, &Config{AllowedMethods: []string{"regex:eth_(call|estimateGas|getBalance)"}})
	benchServeHTTP(b, h, singleSmall)
}

func BenchmarkBlockAndAllow(b *testing.B) {
	h := newBenchPlugin(b, &Config{
		BlockedMethods: []string{"eth_sendRawTransaction"},
		AllowedMethods: []string{"eth_*"},
	})
	benchServeHTTP(b, h, singleSmall)
}

func BenchmarkRejected(b *testing.B) {
	h := newBenchPlugin(b, &Config{BlockedMethods: []string{"eth_call"}})
	benchServeHTTP(b, h, singleSmall)
}

func BenchmarkLargeBody(b *testing.B) {
	h := newBenchPlugin(b, &Config{AllowedMethods: []string{"eth_*"}})
	benchServeHTTP(b, h, singleLarge)
}

func BenchmarkMethodFieldLast(b *testing.B) {
	h := newBenchPlugin(b, &Config{AllowedMethods: []string{"eth_*"}})
	body := `{"jsonrpc":"2.0","id":1,"params":["0x1","0x2","0x3"],"method":"eth_call"}`
	benchServeHTTP(b, h, body)
}

func BenchmarkBatch(b *testing.B) {
	for _, size := range []int{1, 5, 10, 50} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			h := newBenchPlugin(b, &Config{AllowedMethods: []string{"eth_*"}})
			body := buildBatch(size)
			benchServeHTTP(b, h, body)
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
	rw := newDiscardResponseWriter()
	optReq := &http.Request{
		Method: http.MethodOptions,
		URL:    &url.URL{Path: "/"},
		Proto:  "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: make(http.Header),
		Host:   "localhost",
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rw.reset()
			h.ServeHTTP(rw, optReq)
		}
	})
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
