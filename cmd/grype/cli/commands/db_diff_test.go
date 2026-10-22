package commands

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/v6/diff"
)

func TestDBDiffOutputJSON(t *testing.T) {
	// outputJSON writes each field of the result explicitly; make sure a new field can't be silently left out
	require.Equal(t, []string{"Schema", "Databases", "Packages", "Vulnerabilities"}, fieldNames(reflect.TypeOf(diff.Result{})))

	vuln := func(provider, id string) diff.VulnerabilityID {
		return diff.VulnerabilityID{Provider: provider, ID: id}
	}
	populated := &diff.Result{
		Schema: diff.Schema,
		Databases: diff.DatabaseDiff{
			Before: diff.DatabaseInfo{BuildTimestamp: "2026-07-16T12:36:06Z", ModelVersion: "v6.1.7", Revision: 1, Checksum: "xxh64:1"},
			After:  diff.DatabaseInfo{BuildTimestamp: "2026-07-29T06:57:30Z", ModelVersion: "v6.1.7", Revision: 1},
		},
		Packages: []diff.PackageDiff{
			{
				Ecosystem: "deb",
				Name:      "openssl",
				Vulnerabilities: diff.VulnerabilityChanges{
					Added:    []diff.VulnerabilityID{vuln("debian", "CVE-2026-0001"), vuln("debian", "CVE-2026-0002")},
					Modified: []diff.VulnerabilityID{vuln("debian", "CVE-2025-0001")},
				},
			},
			{
				Ecosystem: "cpe",
				Name:      "a<b>&c",
				CPE:       "cpe:2.3:a:vendor:a\\<b\\>\\&c:*:*:*:*:*:*:*:*",
				Vulnerabilities: diff.VulnerabilityChanges{
					Removed: []diff.VulnerabilityID{vuln("nvd", "CVE-2024-0001")},
				},
			},
			{Name: "no-changes"},
		},
		Vulnerabilities: &diff.VulnerabilityDiff{
			Added:   []diff.VulnerabilityID{vuln("debian", "CVE-2026-0001")},
			Removed: []diff.VulnerabilityID{vuln("", "CVE-2020-0001")},
		},
	}

	tests := []struct {
		name   string
		result *diff.Result
	}{
		{name: "empty", result: &diff.Result{}},
		{name: "populated", result: populated},
		{name: "packages only", result: &diff.Result{Schema: diff.Schema, Packages: populated.Packages}},
		{name: "vulnerabilities only", result: &diff.Result{Schema: diff.Schema, Vulnerabilities: populated.Vulnerabilities}},
		{name: "empty vulnerabilities", result: &diff.Result{Schema: diff.Schema, Vulnerabilities: &diff.VulnerabilityDiff{}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var expected bytes.Buffer
			enc := json.NewEncoder(&expected)
			enc.SetIndent("", "  ")
			require.NoError(t, enc.Encode(tt.result))

			var actual bytes.Buffer
			require.NoError(t, outputJSON(&actual, tt.result))

			require.Equal(t, expected.String(), actual.String())
		})
	}
}

func fieldNames(t reflect.Type) []string {
	var names []string
	for i := range t.NumField() {
		names = append(names, t.Field(i).Name)
	}
	return names
}
