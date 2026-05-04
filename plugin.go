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
	Pattern string        `json:"pattern"`
	Error   *JSONRPCError `json:"error,omitempty"`
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
	// This cab be overridden per blocked method. Default: 403
	BlockStatusCode int `json:"blockStatusCode,omitempty"`

	// BlockError is the JSON-RPC error response used for rejected requests.
	// This can be overridden per blocked method.
	BlockError JSONRPCError `json:"blockError,omitempty"`

	// BadRequestStatusCode is the HTTP status code used for bad requests.
	// Default: 400
	BadRequestStatusCode int `json:"badRequestStatusCode,omitempty"`

	// BadRequestError is the JSON-RPC error response used for bad requests.
	BadRequestError JSONRPCError `json:"badRequestError,omitempty"`

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
	// HTTP 405 Method Not Allowed response will be returned.
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

	defaultBlockErrorCode    = -32601
	defaultBlockErrorMessage = "method not allowed"
	defaultBadRequestCode    = -32600
	defaultBadRequestMessage = "invalid request"

	maxMethodBytes = 256
	maxNestDepth   = 64
	maxGrowHint    = 64 << 10 // 64 KiB; buf grows organically beyond this
)

var DefaultPassthroughHTTPMethods = []string{"OPTIONS"}

// methodBlockedError is returned when a method is explicitly blocked by policy.
type methodBlockedError struct {
	method string
	error  *JSONRPCError
}

func (e *methodBlockedError) Error() string {
	return fmt.Sprintf("method not allowed: %q", e.method)
}

// CreateConfig returns the default Config. Called by Traefik.
func CreateConfig() *Config {
	return &Config{
		MaxBodyBytes:         DefaultMaxBodyBytes,
		BlockStatusCode:      DefaultBlockStatusCode,
		BadRequestStatusCode: DefaultBadRequestStatusCode,
		BlockError: JSONRPCError{
			Code:    defaultBlockErrorCode,
			Message: defaultBlockErrorMessage,
		},
		BadRequestError: JSONRPCError{
			Code:    defaultBadRequestCode,
			Message: defaultBadRequestMessage,
		},
		MaxBatchSize:           DefaultMaxBatchSize,
		PassthroughHTTPMethods: DefaultPassthroughHTTPMethods,
	}
}

type blockedMethodMatcher struct {
	matcher
	err *JSONRPCError
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
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.BlockedMethods) == 0 && len(config.AllowedMethods) == 0 {
		return nil, fmt.Errorf("[%s] blockedMethods or allowedMethods must be configured", name)
	}

	// Compile blocked method patterns.
	blockedMethods := make([]blockedMethodMatcher, len(config.BlockedMethods))
	for i, bm := range config.BlockedMethods {
		m, err := compilePattern(bm.Pattern)
		if err != nil {
			return nil, fmt.Errorf("[%s] blockedMethods[%d] %q: %w",
				name, i, bm.Pattern, err)
		}
		var me *JSONRPCError
		if bm.Error != nil {
			me = mergeErr(bm.Error, defaultBlockErrorCode, defaultBlockErrorMessage)
		}
		blockedMethods[i] = blockedMethodMatcher{matcher: m, err: me}
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

	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if config.BlockStatusCode == 0 {
		config.BlockStatusCode = DefaultBlockStatusCode
	}
	if config.BlockStatusCode < 400 || config.BlockStatusCode > 599 {
		return nil, fmt.Errorf("[%s] blockStatusCode must be 4xx or 5xx, got %d",
			name, config.BlockStatusCode)
	}
	if config.BadRequestStatusCode == 0 {
		config.BadRequestStatusCode = DefaultBadRequestStatusCode
	}
	if bsc := config.BadRequestStatusCode; bsc < 400 || bsc > 599 {
		return nil, fmt.Errorf("[%s] badRequestStatusCode must be 4xx or 5xx, got %d",
			name, bsc)
	}
	if config.MaxBatchSize == 0 {
		config.MaxBatchSize = DefaultMaxBatchSize
	}

	var passthrough map[string]struct{}
	if !config.RestrictHTTPMethods {
		passthroughMethods := DefaultPassthroughHTTPMethods
		if len(config.PassthroughHTTPMethods) > 0 {
			passthroughMethods = config.PassthroughHTTPMethods
		}
		passthrough = make(map[string]struct{}, len(passthroughMethods))
		for _, m := range passthroughMethods {
			passthrough[strings.ToUpper(m)] = struct{}{}
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
		blockError:             mergeErr(&config.BlockError, defaultBlockErrorCode, defaultBlockErrorMessage),
		badRequestError:        mergeErr(&config.BadRequestError, defaultBadRequestCode, defaultBadRequestMessage),
		passthroughHTTPMethods: passthrough,
	}, nil
}

func (f *filterPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		if _, ok := f.passthroughHTTPMethods[req.Method]; !ok {
			rw.WriteHeader(http.StatusMethodNotAllowed)
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
	err := f.evaluate(tee)

	if int64(buf.Len()) > f.maxBodyBytes {
		_ = req.Body.Close()
		f.badRequest(rw)
		return
	}
	if err != nil {
		_ = req.Body.Close()
		//nolint:errorlint // errors.As is not supported in Yaegi.
		if e, ok := err.(*methodBlockedError); ok {
			f.reject(rw, e.error)
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

func (f *filterPlugin) methodAllowed(method string) error {
	for _, m := range f.blockedMethods {
		if m.matches(method) {
			return &methodBlockedError{method: method, error: m.err}
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
	Version string        `json:"jsonrpc"`
	Error   *JSONRPCError `json:"error,omitempty"`
	ID      *string       `json:"id"`
}

func (f *filterPlugin) reject(rw http.ResponseWriter, e *JSONRPCError) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(f.blockStatusCode)

	// Use global default if unset.
	if e == nil {
		e = f.blockError
	}

	//nolint:errchkjson // There is no way for us to log an error from the plugin.
	_ = json.NewEncoder(rw).Encode(&jsonRPCResponse{
		Version: jsonRPCVersion,
		Error:   e,
	})
}

func (f *filterPlugin) badRequest(rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(f.badRequestStatusCode)

	//nolint:errchkjson // There is no way for us to log an error from the plugin.
	_ = json.NewEncoder(rw).Encode(&jsonRPCResponse{
		Version: jsonRPCVersion,
		Error:   f.badRequestError,
	})
}

func (f *filterPlugin) evaluate(r io.Reader) error {
	dec := json.NewDecoder(r)
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("read first token: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return fmt.Errorf("unexpected token type: %T", tok)
	}

	switch d {
	case '{':
		if err := f.evaluateObject(dec); err != nil {
			return err
		}

	case '[':
		if !dec.More() {
			return errors.New("empty batch array")
		}
		var count int
		for dec.More() {
			count++
			if count > f.maxBatchSize {
				return fmt.Errorf("batch size exceeds %d", f.maxBatchSize)
			}
			if err := f.evaluateBatchElement(dec); err != nil {
				return err
			}
		}
		if tok, err = dec.Token(); err != nil {
			return fmt.Errorf("read ']': %w", err)
		} else if d, ok = tok.(json.Delim); !ok || d != ']' {
			return fmt.Errorf("expected ']', got %q", tok)
		}

	default:
		return fmt.Errorf("unexpected delim token: %q", d)
	}

	tok, err = dec.Token()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("trailing content: %w", err)
	}
	return fmt.Errorf("unexpected trailing token: %q", tok)
}

func (f *filterPlugin) evaluateBatchElement(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("read batch element: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("batch element must be object, got %q", tok)
	}
	return f.evaluateObject(dec)
}

func (f *filterPlugin) evaluateObject(dec *json.Decoder) error {
	var found bool

	for dec.More() {
		// Read key.
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("read object key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("expected string key, got %T", keyTok)
		}

		if key != "method" {
			if err := skipValue(dec); err != nil {
				return fmt.Errorf("skip %q: %w", key, err)
			}
			continue
		}

		if found {
			return errors.New("duplicate method field")
		}

		// Read method value; must be a string per JSON-RPC spec.
		valTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("read %q value: %w", key, err)
		}
		method, ok := valTok.(string)
		if !ok {
			if d, ok := valTok.(json.Delim); ok {
				// Value is an array or object; skip the compound body.
				if err := skipCompound(dec, d); err != nil {
					return fmt.Errorf("skip delim: %w", err)
				}
			}
			return fmt.Errorf("expected string method value, got %T", valTok)
		}

		if len(method) > maxMethodBytes {
			return fmt.Errorf("method name exceeds %d bytes", maxMethodBytes)
		}

		found = true
		if err = f.methodAllowed(method); err != nil {
			return err
		}
	}

	if tok, err := dec.Token(); err != nil {
		return fmt.Errorf("read '}': %w", err)
	} else if d, ok := tok.(json.Delim); !ok || d != '}' {
		return fmt.Errorf("expected '}', got %q", tok)
	}

	// JSON-RPC request object must contain a method field.
	if !found {
		return errors.New("missing method field")
	}
	return nil
}

func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	return skipCompound(dec, d)
}

func skipCompound(dec *json.Decoder, opening json.Delim) error {
	// Iterative depth-tracked skip to avoid stack exhaustion on deep nesting.
	type frame struct {
		isObject bool
		needVal  bool // for objects: alternates key / value
	}
	stack := make([]frame, 0, 8)
	stack = append(stack, frame{isObject: opening == '{'})

	for len(stack) > 0 {
		if len(stack) > maxNestDepth {
			return fmt.Errorf("nesting depth exceeds %d", maxNestDepth)
		}

		top := &stack[len(stack)-1]

		if !dec.More() {
			// Consume closing delimiter.
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			d, ok := tok.(json.Delim)
			if !ok {
				return fmt.Errorf("expected closing delimiter, got %T", tok)
			}
			if (top.isObject && d != '}') || (!top.isObject && d != ']') {
				return fmt.Errorf("mismatched closing delimiter %q", d)
			}
			stack = stack[:len(stack)-1]
			continue
		}

		tok, err := dec.Token()
		if err != nil {
			return err
		}

		// In objects, every other token is a key (string) that we just skip.
		if top.isObject && !top.needVal {
			top.needVal = true
			continue
		}
		if top.isObject {
			top.needVal = false
		}

		// If the value is a nested compound, push it onto the stack.
		if d, ok := tok.(json.Delim); ok {
			stack = append(stack, frame{isObject: d == '{'})
		}
	}

	return nil
}

func mergeErr(er *JSONRPCError, defaultCode int, defaultMessage string) *JSONRPCError {
	if er.Code == 0 {
		er.Code = defaultCode
	}
	if er.Message == "" {
		er.Message = defaultMessage
	}
	return er
}
