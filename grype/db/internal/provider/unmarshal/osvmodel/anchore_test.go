package osvmodel

import (
	"reflect"
	"testing"
)

// TestAffectedExtension covers the AnchoreAffected typed view over
// affected[].database_specific["anchore"].
//
// Every OSV strategy reads through this helper to decide fix disposition.
// The dominant shape today is the vunnel-stamped {"status": "wont-fix"}
// from the VEX overlay; missing-key and malformed cases must both yield
// the zero value so strategies stay tolerant of vunnel write-side bugs.
func TestAffectedExtension(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]any
		want AnchoreAffected
	}{
		{
			name: "wont-fix status",
			in: map[string]any{
				"anchore": map[string]any{"status": "wont-fix"},
			},
			want: AnchoreAffected{Status: "wont-fix"},
		},
		{
			name: "empty anchore object",
			in: map[string]any{
				"anchore": map[string]any{},
			},
			want: AnchoreAffected{},
		},
		{
			name: "missing anchore key",
			in: map[string]any{
				"vendor": map[string]any{"status": "wont-fix"},
			},
			want: AnchoreAffected{},
		},
		{
			name: "nil map",
			in:   nil,
			want: AnchoreAffected{},
		},
		{
			// future-compatible: vunnel might emit other status values; the
			// decode succeeds, and downstream strategies decide what to do
			// with unknown values via their own switch (see ubuntu).
			name: "unknown status passes through",
			in: map[string]any{
				"anchore": map[string]any{"status": "some-future-value"},
			},
			want: AnchoreAffected{Status: "some-future-value"},
		},
		{
			// type mismatch (status is an int, not a string) → swallowed
			// silently per the helper contract. The transformer falls back
			// to the default branch.
			name: "type mismatch yields zero value",
			in: map[string]any{
				"anchore": map[string]any{"status": 42},
			},
			want: AnchoreAffected{},
		},
		{
			// anchore key is the wrong shape entirely (string instead of object).
			// Decode fails silently.
			name: "anchore key with non-object value",
			in: map[string]any{
				"anchore": "not an object",
			},
			want: AnchoreAffected{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AffectedExtension(tt.in)
			if got != tt.want {
				t.Errorf("AffectedExtension() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRangeExtension covers the AnchoreRange typed view over
// ranges[].database_specific["anchore"]. This is the fix-availability
// channel: vunnel stamps {"fixes": [{"version", "kind", "date"}]} per
// range, and grype's extractFixAvailability reads it through here.
func TestRangeExtension(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]any
		want AnchoreRange
	}{
		{
			name: "single fix entry",
			in: map[string]any{
				"anchore": map[string]any{
					"fixes": []any{
						map[string]any{"version": "1.2.3", "kind": "advisory", "date": "2024-01-01"},
					},
				},
			},
			want: AnchoreRange{
				Fixes: []AnchoreFix{{Version: "1.2.3", Kind: "advisory", Date: "2024-01-01"}},
			},
		},
		{
			name: "multiple fix entries preserved in order",
			in: map[string]any{
				"anchore": map[string]any{
					"fixes": []any{
						map[string]any{"version": "1.0", "kind": "first-observed", "date": "2024-01-01"},
						map[string]any{"version": "1.1", "kind": "advisory", "date": "2024-02-01"},
					},
				},
			},
			want: AnchoreRange{
				Fixes: []AnchoreFix{
					{Version: "1.0", Kind: "first-observed", Date: "2024-01-01"},
					{Version: "1.1", Kind: "advisory", Date: "2024-02-01"},
				},
			},
		},
		{
			name: "missing anchore key",
			in:   map[string]any{"other": "data"},
			want: AnchoreRange{},
		},
		{
			name: "anchore present but no fixes key",
			in: map[string]any{
				"anchore": map[string]any{"status": "wont-fix"},
			},
			want: AnchoreRange{},
		},
		{
			name: "empty fixes array",
			in: map[string]any{
				"anchore": map[string]any{"fixes": []any{}},
			},
			want: AnchoreRange{Fixes: []AnchoreFix{}},
		},
		{
			name: "nil map",
			in:   nil,
			want: AnchoreRange{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RangeExtension(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RangeExtension() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestDecodeNamespace exercises the namespaced-decode entry point directly.
// Used by AffectedExtension/RangeExtension and by per-vendor extension
// helpers that namespace under their own key.
func TestDecodeNamespace(t *testing.T) {
	type sample struct {
		Name string `json:"name"`
		Age  int    `json:"age,omitempty"`
	}

	tests := []struct {
		name string
		m    map[string]any
		key  string
		want sample
	}{
		{
			name: "namespaced value decodes",
			m:    map[string]any{"vendor": map[string]any{"name": "alice", "age": 30}},
			key:  "vendor",
			want: sample{Name: "alice", Age: 30},
		},
		{
			name: "missing key yields zero value",
			m:    map[string]any{"other": map[string]any{"name": "alice"}},
			key:  "vendor",
			want: sample{},
		},
		{
			name: "empty map yields zero value",
			m:    map[string]any{},
			key:  "vendor",
			want: sample{},
		},
		{
			name: "nil map yields zero value",
			m:    nil,
			key:  "vendor",
			want: sample{},
		},
		{
			// unrelated keys present alongside the target — only the target is decoded.
			name: "ignores sibling keys",
			m: map[string]any{
				"vendor": map[string]any{"name": "alice"},
				"other":  map[string]any{"name": "bob"},
			},
			key:  "vendor",
			want: sample{Name: "alice"},
		},
		{
			// JSON-incompatible value at the key → decode fails silently,
			// caller gets zero value.
			name: "type mismatch yields zero value",
			m:    map[string]any{"vendor": "not an object"},
			key:  "vendor",
			want: sample{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got sample
			DecodeNamespace(tt.m, tt.key, &got)
			if got != tt.want {
				t.Errorf("DecodeNamespace() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestDecodeAll exercises the top-level-decode entry point. Used when a
// vendor sticks their fields directly at the root of database_specific or
// ecosystem_specific (alma's rpm_modularity is the dominant example).
func TestDecodeAll(t *testing.T) {
	type rpm struct {
		RpmModularity string `json:"rpm_modularity,omitempty"`
	}

	tests := []struct {
		name string
		m    map[string]any
		want rpm
	}{
		{
			name: "top-level field decodes",
			m:    map[string]any{"rpm_modularity": "nodejs:18"},
			want: rpm{RpmModularity: "nodejs:18"},
		},
		{
			name: "absent field yields zero value",
			m:    map[string]any{"other_field": "x"},
			want: rpm{},
		},
		{
			name: "empty map is a no-op (early return)",
			m:    map[string]any{},
			want: rpm{},
		},
		{
			name: "nil map is a no-op (early return)",
			m:    nil,
			want: rpm{},
		},
		{
			// extra keys are ignored at the json decode boundary
			name: "extra keys ignored",
			m: map[string]any{
				"rpm_modularity": "nodejs:18",
				"future_field":   42,
			},
			want: rpm{RpmModularity: "nodejs:18"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got rpm
			DecodeAll(tt.m, &got)
			if got != tt.want {
				t.Errorf("DecodeAll() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
