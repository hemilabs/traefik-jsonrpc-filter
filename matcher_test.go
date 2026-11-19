// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package traefik_jsonrpc_filter

import "testing"

func TestCompilePattern(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			pattern string
			input   string
			want    bool
		}{
			// Exact.
			{"eth_call", "eth_call", true},
			{"eth_call", "eth_Call", false},
			{"eth_call", "eth_call2", false},
			{"eth_call", "xeth_call", false},

			// Prefix.
			{"debug_*", "debug_traceTransaction", true},
			{"debug_*", "debug_", true},
			{"debug_*", "debug", false},
			{"debug_*", "xdebug_foo", false},
			{"eth_*", "eth_sendRawTransaction", true},
			{"eth_*", "net_version", false},

			// Suffix.
			{"*_admin", "eth_admin", true},
			{"*_admin", "_admin", true},
			{"*_admin", "admin", false},
			{"*_admin", "eth_admin_x", false},

			// Contains.
			{"*debug*", "eth_debug_trace", true},
			{"*debug*", "debug", true},
			{"*debug*", "debugX", true},
			{"*debug*", "Xdebug", true},
			{"*debug*", "debu", false},

			// Regex - auto-anchored.
			{"regex:debug_.*", "debug_traceBlock", true},
			{"regex:debug_.*", "not_debug_trace", false},
			{"regex:eth_(call|estimateGas)", "eth_call", true},
			{"regex:eth_(call|estimateGas)", "eth_estimateGas", true},
			{"regex:eth_(call|estimateGas)", "eth_sendTransaction", false},

			// Regex - already anchored.
			{"regex:^debug_.*$", "debug_traceBlock", true},
			{"regex:^debug_.*$", "not_debug_trace", false},
		}
		for _, tt := range tests {
			t.Run(tt.pattern+"/"+tt.input, func(t *testing.T) {
				t.Parallel()
				m, err := compilePattern(tt.pattern)
				if err != nil {
					t.Fatalf("compilePattern(%q): %v", tt.pattern, err)
				}
				if got := m.matches(tt.input); got != tt.want {
					t.Errorf("matches(%q) = %v, want %v", tt.input, got, tt.want)
				}
			})
		}
	})

	t.Run("regex patterns", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			pattern     string
			wantPattern string
		}{
			// Regex patterns are normalised by regexp/syntax before anchoring.
			{"regex:debug_.*", "^(?:(?-s:debug_.*))$"},
			{"regex:.*(debug|admin).*", "^(?:(?-s:.*(debug|admin).*))$"},

			// Regex patterns should be auto-anchored.
			{"regex:test", "^(?:test)$"},
			{"regex:^test", `^(?:\Atest)$`},
			{"regex:test$", "^(?:(?-m:test$))$"},
			{"regex:^test$", `^(?:(?-m:\Atest$))$`},

			// Top-level alternation is anchored as a whole.
			{"regex:debug_.*|admin_.*", "^(?:(?-s:debug_.*|admin_.*))$"},

			// An unterminated quoted region is closed before anchoring.
			{`regex:\Qeth_call$`, `^(?:eth_call\$)$`},

			// Leading/trailing whitespace with anchor will still be auto-anchored.
			{"regex: ^test", `^(?: \Atest)$`},
			{"regex:test$ ", "^(?:(?-m:test$ ))$"},
		}
		for _, tt := range tests {
			t.Run(tt.pattern, func(t *testing.T) {
				t.Parallel()
				m, err := compilePattern(tt.pattern)
				if err != nil {
					t.Fatalf("compilePattern(%q): %v", tt.pattern, err)
				}
				rm, ok := m.(*regexMatcher)
				if !ok {
					t.Fatalf("compilePattern(%q): got %T, want regexMatcher",
						tt.pattern, m)
				}
				if rm.re.String() != tt.wantPattern {
					t.Errorf("compilePattern(%q): got regex %q, want %q",
						tt.pattern, rm.re.String(), tt.wantPattern)
				}
			})
		}
	})

	t.Run("errors", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			pattern string
		}{
			{"regex:"},
			{"regex:[invalid"},
			{"regex:a)|(b"},
			{"foo*bar"},
			{"*foo*bar"},
			{"a*b*c"},
			// "**" is valid and will match everything.
		}
		for _, tt := range tests {
			t.Run(tt.pattern, func(t *testing.T) {
				t.Parallel()
				_, err := compilePattern(tt.pattern)
				if err == nil {
					t.Fatalf("compilePattern(%q): expected error", tt.pattern)
				}
			})
		}
	})
}

func TestMatchBypass(t *testing.T) {
	t.Parallel()
	// Test vectors that test strange method values. Method values come from
	// untrusted JSON-RPC requests; matchers mut compare bytes strictly and
	// never normalise, fold, or trim input.
	tests := []struct {
		pattern string
		input   string
		want    bool
	}{
		// Numeric / non-string-looking inputs.
		{"eth_call", "12345", false},
		{"eth_call", "0", false},
		{"eth_*", "1234", false},
		{"*_call", "999", false},

		// Whitespace.
		{"eth_call", " eth_call", false},
		{"eth_call", "eth_call ", false},
		{"eth_call", "eth_call\n", false},
		{"eth_call", "eth_call\t", false},
		{"eth_call", "eth\u00a0call", false}, // non-breaking space
		{"eth_*", " eth_call", false},
		{"eth_*", "\teth_call", false},
		{"*_admin", "_admin\n", false},

		// Case-folding (matchers are case-sensitive).
		{"eth_call", "ETH_CALL", false},
		{"eth_call", "Eth_Call", false},
		{"eth_*", "ETH_call", false},
		{"*_admin", "eth_ADMIN", false},
		{"*debug*", "DEBUG", false},
		{"regex:debug_.*", "DEBUG_trace", false},

		// NUL-bytes.
		{"eth_call", "eth_call\x00", false},
		{"eth_call", "\x00eth_call", false},
		{"eth_call", "eth\x00call", false},
		{"eth_*", "\x00eth_call", false},

		// Unicode look-alike / homoglyph inputs (Cyrillic letters).
		{"eth_call", "еth_call", false}, // Cyrillic 'е' (U+0435).
		{"eth_call", "eth_cаll", false}, // Cyrillic 'а' (U+0430).
		{"admin", "аdmin", false},       // Cyrillic 'а' (U+0430).

		// Unicode normalisation is NOT performed; precomposed vs
		// decomposed forms must not match each other.
		{"café", "cafe\u0301", false}, // NFD: e + combining acute
		{"café", "café", true},        // exact NFC bytes
		{"regex:café", "cafe\u0301", false},

		// Other weird Unicode inputs.
		{"eth_call", "eth_call\u200b", false}, // zero-width space appended
		{"eth_call", "\ufeffeth_call", false}, // BOM prefix
		{"eth_call", "eth_call\u202e", false}, // RTL override appended
		{"eth_*", "🚀eth_call", false},

		// Empty / single-character inputs.
		{"eth_call", "", false},
		{"eth_*", "", false},
		{"*_admin", "", false},
		{"*debug*", "", false},
		{"regex:debug_.*", "", false},
		{"*", "", true},  // wildcard matches empty
		{"**", "", true}, // contains-anything matches empty

		// Inputs longer than the pattern with extra content.
		{"eth_call", "eth_call_extra", false},
		{"eth_call", "extra_eth_call", false},
		{"*_admin", "_admin_more", false},
		{"regex:eth_(call|estimateGas)", "eth_call_extra", false},
		{"regex:eth_(call|estimateGas)", "x_eth_call", false},

		// Top-level alternation must be anchored on every branch.
		{"regex:debug_.*|admin_.*", "admin_foo", true},
		{"regex:debug_.*|admin_.*", "x_admin_foo", false},
		{"regex:debug_.*|admin_.*", "x_debug_foo", false},
		{"regex:eth_call|eth_chainId", "eth_callEvil", false},
		{"regex:eth_call|eth_chainId", "x_eth_chainId", false},
		{"regex:^eth_call|eth_chainId$", "eth_callEvil", false},

		// Unterminated quoted regions are literal to the end of the pattern.
		{`regex:\Qeth_call$`, "eth_call$", true},
		{`regex:\Qeth_call$`, "eth_call", false},
		{`regex:\Qeth_call$`, "eth_call$x", false},
		{`regex:\Qeth_call|eth_chainId`, "eth_chainId", false},

		// Pure-symbol / control-character inputs.
		{"eth_call", "\n", false},
		{"eth_call", "\t\t\t", false},
		{"eth_*", "!!!", false},
		{"*", "\x00\x01\x02", true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.input, func(t *testing.T) {
			t.Parallel()
			m, err := compilePattern(tt.pattern)
			if err != nil {
				t.Fatalf("compilePattern(%q): %v", tt.pattern, err)
			}
			if got := m.matches(tt.input); got != tt.want {
				t.Errorf("matches(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
