package diff

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/db/v6/testdb"
)

// Test_packageStatusStates covers every combination of the statuses a key can carry on each side of a
// diff. A key — one package, vulnerability, provider and OS release — can have a vulnerable record, a
// not-vulnerable record, both, or neither, independently in each database, so there are 15 states (the
// sixteenth is the key existing in neither database). Deciding added and removed from individual record
// pairs rather than from these sets is what reported a key with both statuses on both sides as added and
// removed at once, so each state is pinned here: a rule derived from one example cannot be checked
// against the states next to it.
func Test_packageStatusStates(t *testing.T) {
	const (
		neither = "neither"
		added   = "added"
		removed = "removed"
	)

	// statuses on each side, as (not-vulnerable, vulnerable)
	tests := []struct {
		o0, o1, n0, n1 bool
		expected       string
	}{
		// the key is only in the new database: added, whatever statuses it has
		{false, false, false, true, added},
		{false, false, true, false, added},
		{false, false, true, true, added},

		// the key is only in the old database: removed
		{false, true, false, false, removed},
		{true, false, false, false, removed},
		{true, true, false, false, removed},

		// identical statuses on both sides: unchanged, including both-statuses (the module-stream case)
		{false, true, false, true, neither},
		{true, false, true, false, neither},
		{true, true, true, true, neither},

		// gaining a not-vulnerable record stops the key matching, so it is removed
		{false, true, true, false, removed},
		{false, true, true, true, removed},

		// losing the not-vulnerable record, or gaining a vulnerable one, makes it match: added
		{true, false, false, true, added},
		{true, false, true, true, added},
		{true, true, false, true, added},

		// a vulnerable record replaced by a not-vulnerable one: removed
		{true, true, true, false, removed},
	}

	inputDir, err := filepath.Abs(filepath.Join("testdata", "inputs"))
	require.NoError(t, err)

	// the fixture starts with a vulnerable record only, so each state is reached by copying it to the
	// unaffected table and/or deleting the affected one
	mutations := func(wantNotVuln, wantVuln bool) []string {
		switch {
		case wantNotVuln && wantVuln:
			return []string{copyHandles("affected_package_handles", "unaffected_package_handles")}
		case wantNotVuln:
			return []string{copyHandles("affected_package_handles", "unaffected_package_handles"), "DELETE FROM affected_package_handles"}
		case wantVuln:
			return nil
		default:
			return []string{"DELETE FROM affected_package_handles"}
		}
	}
	name := func(o0, o1, n0, n1 bool) string {
		b := func(v bool) string {
			if v {
				return "1"
			}
			return "0"
		}
		return "old_" + b(o0) + b(o1) + "_new_" + b(n0) + b(n1)
	}

	for _, tt := range tests {
		t.Run(name(tt.o0, tt.o1, tt.n0, tt.n1), func(t *testing.T) {
			oldDB := filepath.Join(t.TempDir(), "oldDB")
			testdb.BuildFromFlatFileDir(t, time.Date(2022, 8, 11, 18, 1, 5, 0, time.UTC), oldDB, inputDir, "cve-2025-59800")
			execSQL(t, oldDB, mutations(tt.o0, tt.o1)...)

			newDB := filepath.Join(t.TempDir(), "newDB")
			testdb.BuildFromFlatFileDir(t, time.Date(2022, 8, 12, 1, 55, 19, 0, time.UTC), newDB, inputDir, "cve-2025-59800")
			execSQL(t, newDB, mutations(tt.n0, tt.n1)...)

			differ, err := NewDBDiffer(Config{Config: installation.Config{}, OldDB: oldDB, NewDB: newDB})
			require.NoError(t, err)
			t.Cleanup(func() { _ = differ.Close() })

			result, err := differ.Diff()
			require.NoError(t, err)

			var gotAdded, gotRemoved []VulnerabilityID
			for _, p := range result.Packages {
				if p.Name != "ghostscript" {
					continue
				}
				gotAdded = append(gotAdded, p.Vulnerabilities.Added...)
				gotRemoved = append(gotRemoved, p.Vulnerabilities.Removed...)
			}

			switch tt.expected {
			case added:
				require.NotEmpty(t, gotAdded, "expected the vulnerability added")
				require.Empty(t, gotRemoved, "expected it not also removed")
			case removed:
				require.NotEmpty(t, gotRemoved, "expected the vulnerability removed")
				require.Empty(t, gotAdded, "expected it not also added")
			default:
				require.Empty(t, gotAdded, "expected no addition")
				require.Empty(t, gotRemoved, "expected no removal")
			}
		})
	}
}
