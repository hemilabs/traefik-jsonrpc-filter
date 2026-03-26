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

	t.Run("errors", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			pattern string
		}{
			{"regex:"},
			{"regex:[invalid"},
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
