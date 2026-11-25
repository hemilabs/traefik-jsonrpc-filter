// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package yaegi

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type discardResponseWriter struct {
	header http.Header
	code   int
}

func (w *discardResponseWriter) Header() http.Header         { return w.header }
func (w *discardResponseWriter) WriteHeader(code int)        { w.code = code }
func (w *discardResponseWriter) Write(b []byte) (int, error) { return len(b), nil }

var benchConfig = map[string]any{"allowedMethods": []any{"eth_*", "net_*", "web3_*"}}

type benchCase struct {
	name   string
	method string
	body   string
	status int
}

func benchCases() []benchCase {
	const small = `{"jsonrpc":"2.0","method":"eth_call","id":1}`

	// ~900 KiB params object of many small values.
	var largeParams strings.Builder
	largeParams.WriteString(`{"jsonrpc":"2.0","method":"eth_call","params":{`)
	for i := 0; largeParams.Len() < 900<<10; i++ {
		if i > 0 {
			largeParams.WriteByte(',')
		}
		_, _ = fmt.Fprintf(&largeParams, `"k%d":[1,{"a":"b"},null]`, i)
	}
	largeParams.WriteString(`},"id":1}`)

	return []benchCase{
		{name: "Passthrough", method: http.MethodOptions, status: http.StatusOK},
		{name: "Allowed", body: small, status: http.StatusOK},
		{name: "Rejected", body: `{"jsonrpc":"2.0","method":"debug_traceTransaction","id":1}`, status: http.StatusForbidden},
		{name: "Realistic", body: `{"jsonrpc":"2.0","method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000001","to":"0x0000000000000000000000000000000000000002","gas":"0x76c0","gasPrice":"0x9184e72a000","value":"0x9184e72a","data":"0x17886c6e487ba2ce30038eddabad1ae879471423709dd47762dc0af182d4749337d912d65e97eeba7e"},"latest"],"id":1}`, status: http.StatusOK},
		{name: "MethodFieldLast", body: `{"jsonrpc":"2.0","id":1,"params":[{"to":"0x0000000000000000000000000000000000000000","data":"0x00"},"latest",1,2,3,4,5,6,7,8],"method":"eth_call"}`, status: http.StatusOK},
		{name: "LargeBody", body: `{"jsonrpc":"2.0","method":"eth_call","params":["` + strings.Repeat("x", 4096) + `"],"id":1}`, status: http.StatusOK},
		{name: "Batch10", body: "[" + strings.Repeat(small+",", 9) + small + "]", status: http.StatusOK},
		{name: "LargeParams", body: largeParams.String(), status: http.StatusOK},
	}
}

// newRequest returns a request template; serveCopy sets a fresh body per call.
func (bc benchCase) newRequest(b *testing.B) *http.Request {
	b.Helper()
	method := bc.method
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(b.Context(), method, "/", http.NoBody)
	if err != nil {
		b.Fatal(err)
	}
	return req
}

func (bc benchCase) serveCopy(h http.Handler, rw *discardResponseWriter, tmpl *http.Request) {
	clear(rw.header)
	rw.code = 0
	req := *tmpl
	if bc.body != "" {
		req.Body = io.NopCloser(strings.NewReader(bc.body))
		req.ContentLength = int64(len(bc.body))
	}
	h.ServeHTTP(rw, &req)
}

func reportThroughput(b *testing.B) {
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "req/s")
}

// BenchmarkServeHTTP measures sequential requests through one middleware.
func BenchmarkServeHTTP(b *testing.B) {
	h := newInterpreted(b, benchConfig)
	for _, bc := range benchCases() {
		b.Run(bc.name, func(b *testing.B) {
			tmpl := bc.newRequest(b)
			rw := &discardResponseWriter{header: make(http.Header)}
			b.ReportAllocs()
			for b.Loop() {
				bc.serveCopy(h, rw, tmpl)
			}
			if rw.code != bc.status {
				b.Fatalf("status = %d, want %d", rw.code, bc.status)
			}
			reportThroughput(b)
		})
	}
}

// BenchmarkServeHTTPParallel measures concurrent requests through one
// middleware, as Traefik serves them; set the number of goroutines with -cpu.
func BenchmarkServeHTTPParallel(b *testing.B) {
	h := newInterpreted(b, benchConfig)
	for _, bc := range benchCases() {
		b.Run(bc.name, func(b *testing.B) {
			tmpl := bc.newRequest(b)
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				rw := &discardResponseWriter{header: make(http.Header)}
				served := false
				for pb.Next() {
					bc.serveCopy(h, rw, tmpl)
					served = true
				}
				if served && rw.code != bc.status {
					b.Errorf("status = %d, want %d", rw.code, bc.status)
				}
			})
			reportThroughput(b)
		})
	}
}

// BenchmarkNew measures building a middleware with a large configuration, as
// Traefik does for each middleware on configuration reload.
func BenchmarkNew(b *testing.B) {
	allowed := make([]any, 0, 150)
	blocked := make([]any, 0, 50)
	for i := range 50 {
		allowed = append(allowed,
			fmt.Sprintf("ns%d_method", i),
			fmt.Sprintf("ns%d_*", i),
			fmt.Sprintf("regex:ns%d_(get|set)[A-Z][a-z]+", i))
		blocked = append(blocked, map[string]any{"pattern": fmt.Sprintf("*_admin%d*", i)})
	}
	cfg := map[string]any{"allowedMethods": allowed, "blockedMethods": blocked}

	b.ReportAllocs()
	for b.Loop() {
		newInterpreted(b, cfg)
	}
}
