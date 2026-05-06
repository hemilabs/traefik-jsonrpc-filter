// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package traefik_jsonrpc_filter

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type matcher interface {
	matches(value string) bool
}

type exactMatcher struct{ s string }

func (m *exactMatcher) matches(v string) bool {
	return v == m.s
}

type prefixMatcher struct{ s string }

func (m *prefixMatcher) matches(v string) bool {
	return strings.HasPrefix(v, m.s)
}

type suffixMatcher struct{ s string }

func (m *suffixMatcher) matches(v string) bool {
	return strings.HasSuffix(v, m.s)
}

type containsMatcher struct{ s string }

func (m *containsMatcher) matches(v string) bool {
	return strings.Contains(v, m.s)
}

type regexMatcher struct{ re *regexp.Regexp }

func (m *regexMatcher) matches(v string) bool {
	return m.re.MatchString(v)
}

func compilePattern(raw string) (matcher, error) {
	// Regexp.
	if expr, ok := strings.CutPrefix(raw, "regex:"); ok {
		if expr == "" {
			return nil, errors.New("empty regex pattern")
		}

		// Auto-anchor to prevent accidental partial matches.
		//
		// Security: "debug" must not match "not_debug" unless the pattern
		// explicitly allows it, e.g. ".*debug.*".
		if expr[0] != '^' {
			expr = "^" + expr
		}
		if expr[len(expr)-1] != '$' {
			expr = expr + "$"
		}

		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", raw, err)
		}
		return &regexMatcher{re}, nil
	}

	// Glob patterns.
	n := strings.Count(raw, "*")
	switch {
	case n == 0:
		return &exactMatcher{raw}, nil
	case n == 1 && strings.HasSuffix(raw, "*"):
		return &prefixMatcher{s: raw[:len(raw)-1]}, nil
	case n == 1 && strings.HasPrefix(raw, "*"):
		return &suffixMatcher{s: raw[1:]}, nil
	case n == 2 && strings.HasPrefix(raw, "*") && strings.HasSuffix(raw, "*"):
		inner := raw[1 : len(raw)-1]
		return &containsMatcher{inner}, nil
	}
	return nil, fmt.Errorf("unsupported glob pattern %q: only prefix*, *suffix, and *contains* are supported", raw)
}
