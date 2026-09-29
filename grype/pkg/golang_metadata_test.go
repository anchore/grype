package pkg

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestGolangBinMetadata_isGoCmpSafe guards the constraint that motivated removing the derived symbol
// index from this struct: GolangBinMetadata is part of grype's public library API and match results
// are compared with google/go-cmp (in grype's own integration tests and by external consumers).
// go-cmp panics on the mere presence of an unexported field, so this type must have none. If a future
// change adds one, this test fails instead of a downstream go-cmp comparison panicking.
func TestGolangBinMetadata_isGoCmpSafe(t *testing.T) {
	for _, f := range reflect.VisibleFields(reflect.TypeFor[GolangBinMetadata]()) {
		if !f.IsExported() {
			t.Errorf("GolangBinMetadata has unexported field %q; this makes go-cmp panic for library "+
				"consumers comparing match results — keep the type free of unexported fields", f.Name)
		}
	}

	// sanity: two populated values compare without panicking
	a := GolangBinMetadata{GoCompiledVersion: "go1.22.0", Symbols: map[string][]string{"net/http": {"Serve"}}}
	b := GolangBinMetadata{GoCompiledVersion: "go1.22.0", Symbols: map[string][]string{"net/http": {"Serve"}}}
	if diff := cmp.Diff(a, b); diff != "" {
		t.Errorf("expected equal, got diff:\n%s", diff)
	}
}
