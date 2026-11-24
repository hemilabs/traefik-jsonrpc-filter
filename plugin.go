// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package traefik_jsonrpc_filter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	// jsonRPCVersion is the JSON-RPC specification version used by the plugin.
	jsonRPCVersion = "2.0"
)

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type BlockedMethod struct {
	Pattern    string        `json:"pattern"`
	StatusCode int           `json:"statusCode,omitempty"`
	Error      *JSONRPCError `json:"error,omitempty"`
}

type Config struct {
	// BlockedMethods is a list of patterns to reject.
	// Supports exact match, prefix*, *suffix, *contains*, and regex:<expr>
	// Evaluated before AllowedMethods.
	BlockedMethods []BlockedMethod `json:"blockedMethods,omitempty"`

	// AllowedMethods, if non-empty, enables allowlist mode.
	// Only methods matching at least one allowed pattern AND not matching any
	// blocked patterns are permitted.
	AllowedMethods []string `json:"allowedMethods,omitempty"`

	// MaxBodyBytes is the maximum number of bytes the plugin will read from
	// the request body during inspection. Requests exceeding this are rejected.
	// Default: 1048576 (1 MiB).
	MaxBodyBytes int64 `json:"maxBodyBytes,omitempty"`

	// BlockStatusCode is the HTTP status code used for rejected requests.
	// This can be overridden per blocked method. Default: 403
	BlockStatusCode int `json:"blockStatusCode,omitempty"`

	// BlockError is the JSON-RPC error response used for rejected requests.
	// This can be overridden per blocked method.
	BlockError *JSONRPCError `json:"blockError,omitempty"`

	// BadRequestStatusCode is the HTTP status code used for bad requests.
	// Default: 400
	BadRequestStatusCode int `json:"badRequestStatusCode,omitempty"`

	// BadRequestError is the JSON-RPC error response used for bad requests.
	BadRequestError *JSONRPCError `json:"badRequestError,omitempty"`

	// MaxBatchSize is the maximum number of elements allowed in a JSON-RPC
	// batch array. Requests exceeding this are rejected.
	// Default: 100
	MaxBatchSize int `json:"maxBatchSize,omitempty"`

	// RestrictHTTPMethods, when true, rejects all non-POST requests with HTTP 405
	// and ignores PassthroughHTTPMethods. Use this for strict JSON-RPC enforcement.
	// Default: false
	RestrictHTTPMethods bool `json:"restrictHTTPMethods,omitempty"`

	// PassthroughHTTPMethods is a list of HTTP methods that bypass inspection
	// and are passed directly to the next handler. POST requests will always
	// be inspected. If a request method is not POST and is not listed, an
	// HTTP 405 Method Not Allowed response will be returned. Passthrough
	// requests with a body are rejected as bad requests, as the body is not
	// inspected.
	// Ignored when RestrictHTTPMethods is true.
	//
	// Default: ["OPTIONS"] (preserves CORS preflight)
	PassthroughHTTPMethods []string `json:"passthroughHTTPMethods,omitempty"`
}

const (
	DefaultMaxBodyBytes         int64 = 1 << 20
	DefaultBlockStatusCode      int   = http.StatusForbidden
	DefaultBadRequestStatusCode int   = http.StatusBadRequest
	DefaultMaxBatchSize         int   = 100

	maxMethodBytes = 256
	maxIDBytes     = 256
	maxGrowHint    = 64 << 10 // 64 KiB; buf grows organically beyond this
)

var (
	DefaultPassthroughHTTPMethods = []string{"OPTIONS"}

	defaultBlockError = &JSONRPCError{
		Code:    -32601,
		Message: "method not allowed",
	}
	defaultBadReqError = &JSONRPCError{
		Code:    -32600,
		Message: "invalid request",
	}
)

// methodBlockedError is returned when a method is explicitly blocked by policy.
type methodBlockedError struct {
	method     string
	statusCode int
	error      *JSONRPCError
}

func (e *methodBlockedError) Error() string {
	return fmt.Sprintf("method not allowed: %q", e.method)
}

// CreateConfig returns the default Config. Called by Traefik.
//
// Traefik decodes configuration into the returned value in place, so it must
// not share pointers or slices with the package defaults.
func CreateConfig() *Config {
	blockErr := *defaultBlockError
	badReqErr := *defaultBadReqError
	return &Config{
		MaxBodyBytes:           DefaultMaxBodyBytes,
		BlockStatusCode:        DefaultBlockStatusCode,
		BadRequestStatusCode:   DefaultBadRequestStatusCode,
		BlockError:             &blockErr,
		BadRequestError:        &badReqErr,
		MaxBatchSize:           DefaultMaxBatchSize,
		PassthroughHTTPMethods: append([]string(nil), DefaultPassthroughHTTPMethods...),
	}
}

type blockedMethodMatcher struct {
	m          matcher
	statusCode int
	err        *JSONRPCError
}

type filterPlugin struct {
	next http.Handler
	name string

	blockedMethods []blockedMethodMatcher
	allowedMethods []matcher

	blockStatusCode      int
	badRequestStatusCode int
	blockError           *JSONRPCError
	badRequestError      *JSONRPCError

	maxBodyBytes           int64
	maxBatchSize           int
	passthroughHTTPMethods map[string]struct{}
	// allowHeader is the value of the Allow response header sent with HTTP 405
	// responses. Precomputed at construction (RFC 7231 section 6.5.5).
	allowHeader string
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.BlockedMethods) == 0 && len(config.AllowedMethods) == 0 {
		return nil, fmt.Errorf("[%s] blockedMethods or allowedMethods must be configured", name)
	}

	// Build config (apply defaults, validate, etc.)
	config, err := buildConfig(config)
	if err != nil {
		return nil, fmt.Errorf("[%s] %w", name, err)
	}

	// Compile blocked method patterns.
	blockedMethods := make([]blockedMethodMatcher, len(config.BlockedMethods))
	for i, bm := range config.BlockedMethods {
		if bm.StatusCode != 0 && (bm.StatusCode < 400 || bm.StatusCode > 599) {
			return nil, fmt.Errorf("[%s] blockedMethods[%d].statusCode must be 4xx or 5xx, got %d",
				name, i, bm.StatusCode)
		}
		m, err := compilePattern(bm.Pattern)
		if err != nil {
			return nil, fmt.Errorf("[%s] blockedMethods[%d] %q: %w",
				name, i, bm.Pattern, err)
		}
		blockedMethods[i] = blockedMethodMatcher{
			m:          m,
			statusCode: bm.StatusCode,
			err:        mergeErr(bm.Error, config.BlockError),
		}
	}

	// Compile allowed method patterns.
	allowedMethods := make([]matcher, len(config.AllowedMethods))
	for i, p := range config.AllowedMethods {
		m, err := compilePattern(p)
		if err != nil {
			return nil, fmt.Errorf("[%s] allowedMethods[%d] %q: %w",
				name, i, p, err)
		}
		allowedMethods[i] = m
	}

	// Build passthrough and allowHTTPMethods map
	var passthrough map[string]struct{}
	allowHTTPMethods := []string{http.MethodPost}
	if !config.RestrictHTTPMethods {
		passthrough = make(map[string]struct{}, len(config.PassthroughHTTPMethods))
		for _, m := range config.PassthroughHTTPMethods {
			u := strings.ToUpper(m)
			if _, dup := passthrough[u]; dup {
				continue
			}
			passthrough[u] = struct{}{}
			if u != http.MethodPost {
				allowHTTPMethods = append(allowHTTPMethods, u)
			}
		}
	}

	return &filterPlugin{
		next:                   next,
		name:                   name,
		blockedMethods:         blockedMethods,
		allowedMethods:         allowedMethods,
		maxBodyBytes:           config.MaxBodyBytes,
		maxBatchSize:           config.MaxBatchSize,
		blockStatusCode:        config.BlockStatusCode,
		badRequestStatusCode:   config.BadRequestStatusCode,
		blockError:             config.BlockError,
		badRequestError:        config.BadRequestError,
		passthroughHTTPMethods: passthrough,
		allowHeader:            strings.Join(allowHTTPMethods, ", "),
	}, nil
}

func buildConfig(config *Config) (*Config, error) {
	maxBodyBytes := orDefault(config.MaxBodyBytes, DefaultMaxBodyBytes)
	if maxBodyBytes < 1 {
		return nil, fmt.Errorf("maxBodyBytes must be >= 1: %d", maxBodyBytes)
	}

	blockStatusCode := orDefault(config.BlockStatusCode, DefaultBlockStatusCode)
	if blockStatusCode < 400 || blockStatusCode > 599 {
		return nil, fmt.Errorf("blockStatusCode must be 4xx or 5xx, got %d", blockStatusCode)
	}

	badRequestStatusCode := orDefault(config.BadRequestStatusCode, DefaultBadRequestStatusCode)
	if badRequestStatusCode < 400 || badRequestStatusCode > 599 {
		return nil, fmt.Errorf("badRequestStatusCode must be 4xx or 5xx, got %d", badRequestStatusCode)
	}

	maxBatchSize := orDefault(config.MaxBatchSize, DefaultMaxBatchSize)
	if maxBatchSize < 1 {
		return nil, fmt.Errorf("maxBatchSize must be >= 1: %d", maxBatchSize)
	}

	passthroughMethods := config.PassthroughHTTPMethods
	if len(passthroughMethods) == 0 {
		// Use defaults when empty. To restrict HTTP methods (no passthrough),
		// config should set Config.RestrictHTTPMethods
		passthroughMethods = DefaultPassthroughHTTPMethods
	}

	return &Config{
		BlockedMethods:         config.BlockedMethods,
		AllowedMethods:         config.AllowedMethods,
		MaxBodyBytes:           maxBodyBytes,
		BlockStatusCode:        blockStatusCode,
		BlockError:             mergeErr(config.BlockError, defaultBlockError),
		BadRequestStatusCode:   badRequestStatusCode,
		BadRequestError:        mergeErr(config.BadRequestError, defaultBadReqError),
		MaxBatchSize:           maxBatchSize,
		RestrictHTTPMethods:    config.RestrictHTTPMethods,
		PassthroughHTTPMethods: passthroughMethods,
	}, nil
}

func (f *filterPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		if _, ok := f.passthroughHTTPMethods[req.Method]; !ok {
			rw.Header().Set("Allow", f.allowHeader)
			rw.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Passthrough requests are not inspected, so they must not carry a
		// body: upstreams such as go-ethereum execute a JSON-RPC body
		// regardless of the HTTP method.
		if !bodyEmpty(req.Body) {
			f.badRequest(rw)
			return
		}
		// Passthrough request as-is.
		f.next.ServeHTTP(rw, req)
		return
	}

	// POST request. Inspect body, fail-closed.
	if req.Body == nil {
		f.badRequest(rw)
		return
	}
	if req.ContentLength > f.maxBodyBytes {
		_ = req.Body.Close()
		f.badRequest(rw)
		return
	}

	var buf bytes.Buffer
	if req.ContentLength > 0 && req.ContentLength <= f.maxBodyBytes {
		grow := req.ContentLength
		if grow > maxGrowHint {
			grow = maxGrowHint
		}
		buf.Grow(int(grow))
	}
	limited := io.LimitReader(req.Body, f.maxBodyBytes+1)
	tee := io.TeeReader(limited, &buf)

	// Evaluate request body.
	id, err := f.evaluate(tee)

	if int64(buf.Len()) > f.maxBodyBytes {
		_ = req.Body.Close()
		f.badRequest(rw)
		return
	}
	if err != nil {
		_ = req.Body.Close()
		//nolint:errorlint // errors.As panics in Yaegi; use type assertion instead.
		if e, ok := err.(*methodBlockedError); ok {
			f.reject(rw, id, e.statusCode, e.error)
			return
		}
		f.badRequest(rw)
		return
	}

	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	req.ContentLength = int64(buf.Len())
	f.next.ServeHTTP(rw, req)
}

// bodyEmpty reports whether body contains no data. It reads at most one byte
// rather than trusting Content-Length, which is unknown (-1) for chunked
// requests.
func bodyEmpty(body io.Reader) bool {
	if body == nil {
		return true
	}
	var b [1]byte
	_, err := io.ReadFull(body, b[:])
	return errors.Is(err, io.EOF)
}

func (f *filterPlugin) methodAllowed(method string) error {
	for _, bm := range f.blockedMethods {
		if bm.m.matches(method) {
			return &methodBlockedError{
				method:     method,
				statusCode: bm.statusCode,
				error:      bm.err,
			}
		}
	}
	if len(f.allowedMethods) > 0 {
		for _, m := range f.allowedMethods {
			if m.matches(method) {
				return nil // explicitly allowed
			}
		}
		return &methodBlockedError{method: method}
	}
	return nil // allowed
}

type jsonRPCResponse struct {
	Version string          `json:"jsonrpc"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      json.RawMessage `json:"id"`
}

func (f *filterPlugin) reject(rw http.ResponseWriter, id json.RawMessage, statusCode int, err *JSONRPCError) {
	// Use global defaults if unset.
	// If the method was blocked, err will always be non-nil. In allow-mode,
	// err will be nil when a method was not explicitly blocked or allowed.
	if statusCode == 0 {
		statusCode = f.blockStatusCode
	}
	if err == nil {
		err = f.blockError
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(statusCode)

	//nolint:errchkjson // There is no way for us to log an error from the plugin.
	_ = json.NewEncoder(rw).Encode(&jsonRPCResponse{
		Version: jsonRPCVersion,
		Error:   err,
		ID:      id,
	})
}

func (f *filterPlugin) badRequest(rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(f.badRequestStatusCode)

	// Per the JSON-RPC 2.0 spec, a malformed request that we cannot reliably
	// parse should use an id value of null. We do not attempt to recover the
	// id from a partially parsed body to avoid echoing an untrusted, possibly
	// truncated value.
	//nolint:errchkjson // There is no way for us to log an error from the plugin.
	_ = json.NewEncoder(rw).Encode(&jsonRPCResponse{
		Version: jsonRPCVersion,
		Error:   f.badRequestError,
	})
}

func (f *filterPlugin) evaluate(r io.Reader) (json.RawMessage, error) {
	dec := json.NewDecoder(r)

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read first token: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil, fmt.Errorf("unexpected token type: %T", tok)
	}

	var id json.RawMessage
	switch d {
	case '{':
		id, err = f.evaluateObject(dec)
		if err != nil {
			return id, err
		}

	case '[':
		if !dec.More() {
			return nil, errors.New("empty batch array")
		}
		var count int
		for dec.More() {
			count++
			if count > f.maxBatchSize {
				return nil, fmt.Errorf("batch size exceeds %d", f.maxBatchSize)
			}
			id, err = f.evaluateBatchElement(dec)
			if err != nil {
				return id, err
			}
		}
		// Batch succeeded; per JSON-RPC 2.0 spec, a successful batch response
		// is an array. The middleware does not generate one (the upstream
		// handles the request as-is), so no id is needed.
		id = nil
		if tok, err = dec.Token(); err != nil {
			return nil, fmt.Errorf("read ']': %w", err)
		} else if d, ok = tok.(json.Delim); !ok || d != ']' {
			return nil, fmt.Errorf("expected ']', got %q", tok)
		}

	default:
		return nil, fmt.Errorf("unexpected delim token: %q", d)
	}

	tok, err = dec.Token()
	if errors.Is(err, io.EOF) {
		return id, nil
	}
	if err != nil {
		return id, fmt.Errorf("trailing content: %w", err)
	}
	return id, fmt.Errorf("unexpected trailing token: %q", tok)
}

func (f *filterPlugin) evaluateBatchElement(dec *json.Decoder) (json.RawMessage, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read batch element: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("batch element must be object, got %q", tok)
	}
	return f.evaluateObject(dec)
}

func (f *filterPlugin) evaluateObject(dec *json.Decoder) (json.RawMessage, error) {
	var (
		methodFound bool
		idFound     bool
		id          json.RawMessage
		blockedErr  *methodBlockedError
	)

	for dec.More() {
		// Read key.
		keyTok, err := dec.Token()
		if err != nil {
			return id, fmt.Errorf("read object key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return id, fmt.Errorf("expected string key, got %T", keyTok)
		}

		// Match keys case-insensitively, as encoding/json does when upstreams
		// such as go-ethereum decode the request into a struct, so that keys
		// such as "Method" cannot hide the method from the filter. A second
		// match is rejected as a duplicate field. strings.EqualFold matches
		// the same keys as encoding/json for "method" and "id".
		switch {
		case strings.EqualFold(key, "method"):
			if methodFound {
				return id, errors.New("duplicate method field")
			}

			// Read method value; must be a string per JSON-RPC 2.0 spec.
			valTok, err := dec.Token()
			if err != nil {
				return id, fmt.Errorf("read %q value: %w", key, err)
			}
			method, ok := valTok.(string)
			if !ok {
				return id, fmt.Errorf("expected string method value, got %T", valTok)
			}

			if len(method) > maxMethodBytes {
				return id, fmt.Errorf("method name exceeds %d bytes", maxMethodBytes)
			}

			methodFound = true
			if err := f.methodAllowed(method); err != nil {
				//nolint:errorlint // errors.As panics in Yaegi; use type assertion instead.
				if mbe, ok := err.(*methodBlockedError); ok {
					// Defer returning so a late "id" field can still be
					// captured for the JSON-RPC response.
					blockedErr = mbe
					continue
				}
				return id, err
			}

		case strings.EqualFold(key, "id"):
			if idFound {
				return id, errors.New("duplicate id field")
			}
			idFound = true
			rawID, err := readID(dec)
			if err != nil {
				return id, fmt.Errorf("read id: %w", err)
			}
			id = rawID

		default:
			if err := skipValue(dec); err != nil {
				return id, fmt.Errorf("skip %q: %w", key, err)
			}
		}
	}

	if tok, err := dec.Token(); err != nil {
		return id, fmt.Errorf("read '}': %w", err)
	} else if d, ok := tok.(json.Delim); !ok || d != '}' {
		return id, fmt.Errorf("expected '}', got %q", tok)
	}

	// JSON-RPC request object must contain a method field.
	if !methodFound {
		return id, errors.New("missing method field")
	}
	if blockedErr != nil {
		return id, blockedErr
	}
	return id, nil
}

// maxRawIDBytes is the longest string id literal that can decode to at most
// maxIDBytes (each decoded byte takes at most 6 bytes, as in \u0061).
const maxRawIDBytes = 6*maxIDBytes + 2

// readID reads the next JSON value as a JSON-RPC 2.0 id. Values that are not a
// string, number, or null, or are oversized, are returned as a nil id.
//
// Decode returns exactly one valid JSON value without surrounding whitespace,
// so its first byte determines its type, and compound values are never decoded.
func readID(dec *json.Decoder) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	switch c := raw[0]; {
	case c == '"': // string
		if len(raw) > maxRawIDBytes {
			return nil, nil
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || len(s) > maxIDBytes {
			return nil, nil //nolint:nilerr // safe fallback to null id
		}
		// Re-encode to replace invalid UTF-8 and escape HTML characters.
		b, err := json.Marshal(s)
		if err != nil {
			return nil, nil //nolint:nilerr // safe fallback to null id
		}
		return b, nil
	case c == '-' || ('0' <= c && c <= '9'): // number
		if len(raw) > maxIDBytes {
			return nil, nil
		}
		return raw, nil
	case c == 'n': // null
		return raw, nil
	default: // object, array, or boolean
		return nil, nil
	}
}

// skipValue skips the next JSON value in a single Decode call, as each call
// into the standard library is costly under Yaegi.
func skipValue(dec *json.Decoder) error {
	var v json.RawMessage
	return dec.Decode(&v)
}

func mergeErr(err *JSONRPCError, def *JSONRPCError) *JSONRPCError {
	if err == nil {
		return def
	}
	// Return a fresh struct so we never mutate the caller's *JSONRPCError.
	out := *err
	if out.Code == 0 {
		out.Code = def.Code
	}
	if out.Message == "" {
		out.Message = def.Message
	}
	// Note: if err.Data is nil, it is left as nil instead of copying
	// the data value from default.
	return &out
}

func orDefault[T comparable](a T, b T) T {
	var zero T
	if a == zero {
		return b
	}
	return a
}
