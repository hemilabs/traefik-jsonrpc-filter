// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package yaegi tests and benchmarks the plugin interpreted by Yaegi, loaded
// and configured the way Traefik does (see pkg/plugins/middlewareyaegi.go).
package yaegi

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"

	filter "github.com/hemilabs/traefik-jsonrpc-filter"
)

const importPath = "github.com/hemilabs/traefik-jsonrpc-filter"

// interpreted holds the interpreted CreateConfig and New functions. As in
// Traefik, one interpreter serves every middleware instance.
var interpreted struct{ createConfig, new reflect.Value }

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	goPath, err := os.MkdirTemp("", "yaegi-gopath")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(goPath)

	if err := load(goPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return m.Run()
}

// load interprets the plugin from the repository root.
func load(goPath string) error {
	repo, err := filepath.Abs("../..")
	if err != nil {
		return err
	}
	src := filepath.Join(goPath, "src", importPath)
	if err := os.MkdirAll(filepath.Dir(src), 0o750); err != nil {
		return err
	}
	if err := os.Symlink(repo, src); err != nil {
		return err
	}

	i := interp.New(interp.Options{GoPath: goPath})
	if err := i.Use(stdlib.Symbols); err != nil {
		return err
	}
	if _, err := i.Eval(`import "` + importPath + `"`); err != nil {
		return err
	}
	if interpreted.createConfig, err = i.Eval("traefik_jsonrpc_filter.CreateConfig"); err != nil {
		return err
	}
	interpreted.new, err = i.Eval("traefik_jsonrpc_filter.New")
	return err
}

// decodeConfig decodes cfg into config as Traefik decodes dynamic
// configuration into the value returned by CreateConfig.
func decodeConfig(tb testing.TB, cfg map[string]any, config any) {
	tb.Helper()
	if len(cfg) == 0 {
		return
	}
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.StringToSliceHookFunc(","),
		WeaklyTypedInput: true,
		Result:           config,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if err := dec.Decode(cfg); err != nil {
		tb.Fatal(err)
	}
}

func newInterpreted(tb testing.TB, cfg map[string]any) http.Handler {
	tb.Helper()
	vCfg := interpreted.createConfig.Call(nil)[0]
	decodeConfig(tb, cfg, vCfg.Interface())
	res := interpreted.new.Call([]reflect.Value{
		reflect.ValueOf(tb.Context()), reflect.ValueOf(next), vCfg, reflect.ValueOf("yaegi"),
	})
	if !res[1].IsNil() {
		tb.Fatal(res[1].Interface())
	}
	return res[0].Interface().(http.Handler)
}

func newCompiled(tb testing.TB, cfg map[string]any) http.Handler {
	tb.Helper()
	config := filter.CreateConfig()
	decodeConfig(tb, cfg, config)
	h, err := filter.New(tb.Context(), next, config, "compiled")
	if err != nil {
		tb.Fatal(err)
	}
	return h
}

// next echoes the forwarded body, so tests see what reaches the upstream.
var next = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	for k, v := range r.Header {
		for _, vv := range v {
			rw.Header().Add(k, vv)
		}
	}
	rw.Header().Set("X-Next", "called")
	rw.WriteHeader(http.StatusOK)
	_, _ = io.Copy(rw, r.Body)
})

func TestDifferential(t *testing.T) {
	t.Parallel()

	configs := []struct {
		name string
		cfg  map[string]any
	}{
		{name: "default", cfg: map[string]any{
			"blockedMethods": []any{map[string]any{"pattern": "debug_*"}},
		}},
		{name: "allow", cfg: map[string]any{
			"allowedMethods": []any{"eth_*", "net_version", "regex:web3_(clientVersion|sha3)"},
			"blockedMethods": []any{
				map[string]any{
					"pattern":    "eth_sendRawTransaction",
					"statusCode": 429,
					"error":      map[string]any{"code": -32005, "message": "rate limited", "data": "try later"},
				},
				map[string]any{"pattern": "*_sign*"},
			},
			"maxBatchSize": "3",
			"maxBodyBytes": 4096,
		}},
		{name: "strict", cfg: map[string]any{
			"restrictHTTPMethods":  true,
			"blockedMethods":       []any{map[string]any{"pattern": "regex:debug_.*"}, map[string]any{"pattern": "admin_*"}},
			"blockStatusCode":      451,
			"blockError":           map[string]any{"message": "denied"},
			"badRequestStatusCode": "422",
			"badRequestError":      map[string]any{"code": -32700},
		}},
		{name: "passthrough", cfg: map[string]any{
			"blockedMethods":         []any{map[string]any{"pattern": "debug_*"}},
			"passthroughHTTPMethods": "GET,OPTIONS",
		}},
	}
	type handlers struct{ compiled, interpreted http.Handler }
	hs := make(map[string]handlers, len(configs))
	for _, c := range configs {
		hs[c.name] = handlers{newCompiled(t, c.cfg), newInterpreted(t, c.cfg)}
	}

	const (
		small   = `{"jsonrpc":"2.0","method":"eth_call","id":1}`
		blocked = `{"jsonrpc":"2.0","method":"eth_sendRawTransaction","id":1}`
	)
	blockedWithID := func(id string) string {
		return `{"jsonrpc":"2.0","method":"eth_sendRawTransaction","id":` + id + `}`
	}
	// encoding/json limits each decoded value to 10000 levels of nesting.
	nestedParams := func(depth int) string {
		return `{"jsonrpc":"2.0","method":"eth_call","params":` +
			strings.Repeat("[", depth) + strings.Repeat("]", depth) + `,"id":1}`
	}

	tests := []differentialCase{
		// HTTP methods and passthrough.
		{name: "options passthrough", config: "default", method: http.MethodOptions, status: http.StatusOK},
		{name: "options with body", config: "default", method: http.MethodOptions, body: small, status: http.StatusBadRequest},
		{name: "get not allowed", config: "default", method: http.MethodGet, status: http.StatusMethodNotAllowed},
		{name: "restricted options", config: "strict", method: http.MethodOptions, status: http.StatusMethodNotAllowed},
		{name: "configured get passthrough", config: "passthrough", method: http.MethodGet, status: http.StatusOK},
		{name: "configured get with body", config: "passthrough", method: http.MethodGet, body: small, status: http.StatusBadRequest},
		{name: "put not allowed", config: "passthrough", method: http.MethodPut, status: http.StatusMethodNotAllowed},

		// Malformed requests.
		{name: "nil body", config: "default", nilBody: true, status: http.StatusBadRequest},
		{name: "empty body", config: "default", status: http.StatusBadRequest},
		{name: "invalid json", config: "default", body: `{"method":`, status: http.StatusBadRequest},
		{name: "scalar", config: "default", body: `"eth_call"`, status: http.StatusBadRequest},
		{name: "trailing object", config: "default", body: small + small, status: http.StatusBadRequest},
		{name: "trailing whitespace", config: "default", body: small + "\n", status: http.StatusOK},
		{name: "missing method", config: "default", body: `{"jsonrpc":"2.0","id":1}`, status: http.StatusBadRequest},
		{name: "method not string", config: "default", body: `{"method":1,"id":1}`, status: http.StatusBadRequest},
		{name: "method too long", config: "default", body: `{"method":"` + strings.Repeat("a", 257) + `"}`, status: http.StatusBadRequest},
		{name: "duplicate method", config: "default", body: `{"method":"eth_call","Method":"debug_x"}`, status: http.StatusBadRequest},
		{name: "duplicate id", config: "default", body: `{"method":"eth_call","id":1,"ID":2}`, status: http.StatusBadRequest},
		{name: "custom bad request", config: "strict", body: `{"method":`, status: http.StatusUnprocessableEntity},

		// Body size limits.
		{name: "content length over max", config: "default", body: small, contentLength: 2 << 20, status: http.StatusBadRequest},
		{name: "chunked body over max", config: "allow", body: `{"method":"eth_call","params":"` + strings.Repeat("x", 4096) + `"}`, contentLength: -1, status: http.StatusBadRequest},
		{name: "nesting at limit", config: "default", body: nestedParams(10_000), status: http.StatusOK},
		{name: "nesting over limit", config: "default", body: nestedParams(10_001), status: http.StatusBadRequest},

		// Method matching.
		{name: "allowed glob", config: "allow", body: small, status: http.StatusOK},
		{name: "allowed exact", config: "allow", body: `{"method":"net_version","id":1}`, status: http.StatusOK},
		{name: "allowed regex", config: "allow", body: `{"method":"web3_sha3","id":1}`, status: http.StatusOK},
		{name: "regex anchored", config: "allow", body: `{"method":"web3_sha3x","id":1}`, status: http.StatusForbidden},
		{name: "not allowed", config: "allow", body: `{"method":"debug_traceTransaction","id":1}`, status: http.StatusForbidden},
		{name: "blocked custom error", config: "allow", body: blocked, status: http.StatusTooManyRequests},
		{name: "blocked contains", config: "allow", body: `{"method":"eth_signTransaction","id":1}`, status: http.StatusForbidden},
		{name: "blocked method last", config: "allow", body: `{"id":"abc","params":[{"a":[1,2]}],"method":"eth_sendRawTransaction"}`, status: http.StatusTooManyRequests},
		{name: "case-insensitive keys", config: "allow", body: `{"METHOD":"debug_x","Id":7}`, status: http.StatusForbidden},
		{name: "escaped method", config: "allow", body: `{"method":"eth_send\u0052awTransaction","id":1}`, status: http.StatusTooManyRequests},
		{name: "blocked regex", config: "strict", body: `{"method":"debug_traceTransaction","id":1}`, status: http.StatusUnavailableForLegalReasons},
		{name: "blocked prefix", config: "strict", body: `{"method":"admin_addPeer","id":1}`, status: http.StatusUnavailableForLegalReasons},
		{name: "strict allowed", config: "strict", body: small, status: http.StatusOK},

		// Ids echoed in rejections.
		{name: "id escaped string", config: "allow", body: blockedWithID(`"a\u0062<>&\u00e9"`), status: http.StatusTooManyRequests},
		{name: "id invalid utf-8", config: "allow", body: blockedWithID("\"a\xffb\""), status: http.StatusTooManyRequests},
		{name: "id long string", config: "allow", body: blockedWithID(`"` + strings.Repeat("a", 257) + `"`), status: http.StatusTooManyRequests},
		{name: "id number", config: "allow", body: blockedWithID(`-1.5e+10`), status: http.StatusTooManyRequests},
		{name: "id long number", config: "allow", body: blockedWithID(strings.Repeat("9", 257)), status: http.StatusTooManyRequests},
		{name: "id null", config: "allow", body: blockedWithID(`null`), status: http.StatusTooManyRequests},
		{name: "id object", config: "allow", body: blockedWithID(`{"a":1}`), status: http.StatusTooManyRequests},
		{name: "id array", config: "allow", body: blockedWithID(`[1]`), status: http.StatusTooManyRequests},
		{name: "id bool", config: "allow", body: blockedWithID(`true`), status: http.StatusTooManyRequests},

		// Batches.
		{name: "batch allowed", config: "allow", body: "[" + small + "," + small + "]", status: http.StatusOK},
		{name: "batch with blocked", config: "allow", body: "[" + small + "," + blockedWithID(`"b"`) + "]", status: http.StatusTooManyRequests},
		{name: "batch too large", config: "allow", body: "[" + strings.Repeat(small+",", 3) + small + "]", status: http.StatusBadRequest},
		{name: "empty batch", config: "allow", body: `[]`, status: http.StatusBadRequest},
		{name: "nested batch", config: "allow", body: "[[" + small + "]]", status: http.StatusBadRequest},
		{name: "batch trailing", config: "allow", body: "[" + small + "]x", status: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := hs[tt.config]
			want := tt.serve(t, h.compiled)
			got := tt.serve(t, h.interpreted)

			if want.Code != tt.status {
				t.Fatalf("compiled status = %d, want %d", want.Code, tt.status)
			}
			if got.Code != want.Code {
				t.Errorf("status = %d, compiled %d", got.Code, want.Code)
			}
			if !reflect.DeepEqual(got.Header(), want.Header()) {
				t.Errorf("header = %v, compiled %v", got.Header(), want.Header())
			}
			if got.Body.String() != want.Body.String() {
				t.Errorf("body = %q, compiled %q", got.Body, want.Body)
			}
		})
	}
}

type differentialCase struct {
	name   string
	config string
	method string // defaults to POST
	body   string
	// contentLength overrides the request's Content-Length when non-zero.
	contentLength int64
	nilBody       bool
	status        int
}

func (tc differentialCase) serve(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	method := tc.method
	if method == "" {
		method = http.MethodPost
	}
	req := httptest.NewRequestWithContext(t.Context(), method, "/", strings.NewReader(tc.body))
	if tc.contentLength != 0 {
		req.ContentLength = tc.contentLength
	}
	if tc.nilBody {
		req.Body = nil
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
