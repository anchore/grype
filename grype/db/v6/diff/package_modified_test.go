package diff

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/db/v6/testdb"
)

// Test_packageModifiedRecordSets covers the record sets a key can hold on each side of a diff. One
// package, vulnerability, provider and OS release can have several records describing version ranges, so
// what decides a modification is whether that set of records changed, not whether any single record
// changed. Walking only the old side answers that question for records dropped from the old database but
// not for records added to the new one beside those already there, so each combination is pinned here.
// Only modifications are asserted: whether the same key is also added or removed depends on the statuses
// its records carry, which the added and removed views decide.
func Test_packageModifiedRecordSets(t *testing.T) {
	const (
		blobX = `{"ranges":[{"version":{"type":"dpkg"},"fix":{"state":"not-fixed"}}]}`
		blobY = `{"ranges":[{"version":{"type":"dpkg"},"fix":{"state":"fixed"}}]}`
		blobZ = `{"ranges":[{"version":{"type":"dpkg"},"fix":{"state":"unknown"}}]}`
	)

	// the fixture has a single affected record, so a set is built by replacing its blob and adding records
	replaceRecord := func(v string) []string {
		return []string{`UPDATE blobs SET value = '` + v + `' WHERE id IN (SELECT blob_id FROM affected_package_handles)`}
	}
	addRecord := func(v string) []string {
		return []string{
			`INSERT INTO blobs (value) VALUES ('` + v + `')`,
			`INSERT INTO affected_package_handles (vulnerability_id, operating_system_id, package_id, blob_id)
			 SELECT vulnerability_id, operating_system_id, package_id, (SELECT MAX(id) FROM blobs)
			 FROM affected_package_handles LIMIT 1`,
		}
	}
	addNotVulnerable := []string{copyHandles("affected_package_handles", "unaffected_package_handles")}

	tests := []struct {
		name      string
		mutateOld []string
		mutateNew []string
		modified  bool
	}{
		{name: "same single record", modified: false},
		{name: "the record changed", mutateNew: replaceRecord(blobY), modified: true},
		{name: "a record added beside the existing one", mutateNew: addRecord(blobY), modified: true},
		{name: "a record removed from beside the existing one", mutateOld: addRecord(blobY), modified: true},
		{name: "same two records", mutateOld: addRecord(blobY), mutateNew: addRecord(blobY), modified: false},
		{name: "one of two records changed", mutateOld: addRecord(blobY), mutateNew: addRecord(blobZ), modified: true},
		{name: "two records replaced by one", mutateOld: addRecord(blobY), mutateNew: replaceRecord(blobZ), modified: true},
		{name: "a record added with content already present", mutateNew: addRecord(blobX), modified: false},
		{name: "a record removed with content still present", mutateOld: addRecord(blobX), modified: false},
		{name: "a not-vulnerable record added, vulnerable records unchanged", mutateNew: addNotVulnerable, modified: false},
		{name: "a not-vulnerable record added and a vulnerable record beside it", mutateNew: append(addRecord(blobY), addNotVulnerable...), modified: true},
	}

	inputDir, err := filepath.Abs(filepath.Join("testdata", "inputs"))
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldDB := filepath.Join(t.TempDir(), "oldDB")
			testdb.BuildFromFlatFileDir(t, time.Date(2022, 8, 11, 18, 1, 5, 0, time.UTC), oldDB, inputDir, "cve-2025-59800")
			execSQL(t, oldDB, tt.mutateOld...)

			newDB := filepath.Join(t.TempDir(), "newDB")
			testdb.BuildFromFlatFileDir(t, time.Date(2022, 8, 12, 1, 55, 19, 0, time.UTC), newDB, inputDir, "cve-2025-59800")
			execSQL(t, newDB, tt.mutateNew...)

			differ, err := NewDBDiffer(Config{Config: installation.Config{}, OldDB: oldDB, NewDB: newDB})
			require.NoError(t, err)
			t.Cleanup(func() { _ = differ.Close() })

			result, err := differ.Diff()
			require.NoError(t, err)

			var got []VulnerabilityID
			for _, p := range result.Packages {
				if p.Name == "ghostscript" {
					got = append(got, p.Vulnerabilities.Modified...)
				}
			}
			if tt.modified {
				require.NotEmpty(t, got, "expected the vulnerability modified for the package")
			} else {
				require.Empty(t, got, "expected no modification for the package")
			}
		})
	}
}
