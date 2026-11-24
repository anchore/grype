package v6

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

func archBlob(arch string) *db.PackageBlob {
	if arch == "" {
		return &db.PackageBlob{}
	}
	return &db.PackageBlob{Qualifiers: &db.PackageQualifiers{Architecture: &arch}}
}

func TestArchitectureTally(t *testing.T) {
	tests := []struct {
		name    string
		rows    map[string][]string // provider -> row architectures ("" for none)
		wantErr []string
	}{
		{
			name: "arch-less rows from any provider",
			rows: map[string][]string{"alpine": {"", ""}, "rhel": {""}, "some-new-provider": {""}},
		},
		{
			name: "allowed architectures, mixed with arch-less rows",
			rows: map[string][]string{
				"chainguard":  {"x86_64", "aarch64", ""},
				"hummingbird": {"src", "binary-no-arch-specified"},
				"oracle":      {"x86_64", "aarch64"},
			},
		},
		{
			name:    "architecture from a provider with none allowed",
			rows:    map[string][]string{"rhel": {"x86_64", "", "x86_64"}},
			wantErr: []string{`provider "rhel" emitted architecture "x86_64" on 2 rows (e.g. CVE-rhel-0, CVE-rhel-2)`},
		},
		{
			name:    "deb architecture on dhi, pending a decision on Source-keyed records",
			rows:    map[string][]string{"dhi": {"amd64"}},
			wantErr: []string{`provider "dhi" emitted architecture "amd64" on 1 rows`},
		},
		{
			name: "value outside an allowed provider's list",
			rows: map[string][]string{"chainguard": {"x86_64", "amd64"}, "oracle": {"src"}},
			wantErr: []string{
				`provider "chainguard" emitted architecture "amd64" on 1 rows (e.g. CVE-chainguard-1)`,
				`provider "oracle" emitted architecture "src" on 1 rows`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tally := newArchitectureTally()
			for provider, arches := range tt.rows {
				for i, arch := range arches {
					vuln := &db.VulnerabilityHandle{ProviderID: provider, Name: fmt.Sprint("CVE-", provider, "-", i)}
					tally.record(vuln, archBlob(arch))
				}
			}

			err := tally.summarize()
			if len(tt.wantErr) == 0 {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, want := range tt.wantErr {
				assert.Contains(t, err.Error(), want)
			}
		})
	}
}

func TestArchitectureTally_LimitsAndDedupesExamples(t *testing.T) {
	tally := newArchitectureTally()
	for _, name := range []string{"CVE-1", "CVE-1", "CVE-2", "CVE-3", "CVE-4"} {
		tally.record(&db.VulnerabilityHandle{ProviderID: "ubuntu", Name: name}, archBlob("amd64"))
	}
	err := tally.summarize()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `on 5 rows (e.g. CVE-1, CVE-2, CVE-3)`)
}

// TestWrite_FailsOnUnexpectedArchitecture covers the writer end to end: affected and unaffected rows are
// both tallied, and the build fails at Close, after the whole build has been seen.
func TestWrite_FailsOnUnexpectedArchitecture(t *testing.T) {
	for _, related := range []any{
		db.AffectedPackageHandle{Package: &db.Package{Name: "openssl"}, BlobValue: archBlob("x86_64")},
		db.UnaffectedPackageHandle{Package: &db.Package{Name: "openssl"}, BlobValue: archBlob("x86_64")},
	} {
		w, err := NewWriter(t.TempDir(), provider.States{}, false, 0)
		require.NoError(t, err)

		require.NoError(t, w.Write(data.Entry{
			DBSchemaVersion: db.ModelVersion,
			Data: transformers.RelatedEntries{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:       "CVE-2024-0001",
					ProviderID: "rhel",
					Provider:   &db.Provider{ID: "rhel", Version: "1"},
					BlobValue:  &db.VulnerabilityBlob{ID: "CVE-2024-0001"},
				},
				Related: []any{related},
			},
		}))

		err = w.Close()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `provider "rhel" emitted architecture "x86_64" on 1 rows (e.g. CVE-2024-0001)`)
	}
}

func TestWrite_AllowUnexpectedArchitectures(t *testing.T) {
	w, err := NewWriter(t.TempDir(), provider.States{}, false, 0, WithAllowUnexpectedArchitectures(true))
	require.NoError(t, err)

	require.NoError(t, w.Write(data.Entry{
		DBSchemaVersion: db.ModelVersion,
		Data: transformers.RelatedEntries{
			VulnerabilityHandle: &db.VulnerabilityHandle{
				Name:       "CVE-2024-0001",
				ProviderID: "rhel",
				Provider:   &db.Provider{ID: "rhel", Version: "1"},
				BlobValue:  &db.VulnerabilityBlob{ID: "CVE-2024-0001"},
			},
			Related: []any{db.AffectedPackageHandle{Package: &db.Package{Name: "openssl"}, BlobValue: archBlob("x86_64")}},
		},
	}))

	require.NoError(t, w.Close())
}
