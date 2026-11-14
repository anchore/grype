package osv

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/version"
)

// TestOCamlTransform exercises the ocaml strategy end-to-end against real
// OSEC-* records (as written by the vunnel ocaml provider, including the
// database_specific.anchore.fixes it patches in).
//
//   - OSEC-2017-01: a single introduced/fixed window in the opam ECOSYSTEM range,
//     plus an affected entry without a package holding only GIT ranges, which is
//     dropped.
func TestOCamlTransform(t *testing.T) {
	tests := []transformCase{
		{
			name:        "OSEC-2017-01",
			fixturePath: "testdata/OSEC-2017-01.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "OSEC-2017-01",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2025, time.December, 16, 12, 0, 0, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2017, time.June, 23, 15, 19, 47, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "OSEC-2017-01",
						Description: "## Description\n\nInsufficient sanitisation in the OCaml compiler versions 4.04.0 and 4.04.1 allows external code to be executed with raised privilege in binaries marked as setuid, by setting the CAML_CPLUGINS, CAML_NATIVE_CPLUGINS, or CAML_BYTE_CPLUGINS environment variable.",
						References: []db.Reference{{
							URL:  "https://github.com/ocaml/ocaml/issues/7557",
							Tags: []string{"REPORT"},
						}},
						Aliases: []string{"CVE-2017-9772"},
						Severities: []db.Severity{{
							Scheme: db.SeveritySchemeCVSS,
							Value: db.CVSSSeverity{
								Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								Version: "3.0",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "ocaml",
							Ecosystem: "opam",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2017-9772"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "opam",
									Constraint: ">=4.04,<4.04.2",
								},
								Fix: &db.Fix{
									Version: "4.04.2",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: timeRef(time.Date(2017, time.June, 23, 0, 0, 0, 0, time.UTC)),
											Kind: "advisory",
										},
									},
								},
							}},
						},
					},
				),
			}},
		},
		{
			// only an affected entry without a package holding GIT ranges: nothing to match
			name:        "OSEC-2026-28 without an opam package",
			fixturePath: "testdata/OSEC-2026-28.json",
			want:        nil,
		},
	}

	runTransformCases(t, tests)
}

// TestOCamlTransformMultipleRanges covers OSEC-2026-01, where the opam
// constraint {< "4.14.3" | >= "5" & < "5.4.1"} results in two ECOSYSTEM ranges.
func TestOCamlTransformMultipleRanges(t *testing.T) {
	vulns := loadFixture(t, "testdata/OSEC-2026-01.json")
	require.Len(t, vulns, 1)

	entries, err := Transform(vulns[0], inputProviderState())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	related, ok := entries[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)
	assert.Equal(t, db.VulnerabilityActive, related.VulnerabilityHandle.Status)

	// the GIT-only affected entry is dropped, only the opam package remains
	require.Len(t, related.Related, 1)
	aph, ok := related.Related[0].(db.AffectedPackageHandle)
	require.True(t, ok)
	assert.Equal(t, &db.Package{Name: "ocaml", Ecosystem: "opam"}, aph.Package)
	assert.Equal(t, []string{"CVE-2026-28364", "GHSA-j26j-m5xr-g23c", "GHSA-m34r-cgq7-jhfm"}, aph.BlobValue.CVEs)

	var constraints, fixes []string
	for _, r := range aph.BlobValue.Ranges {
		assert.Equal(t, "opam", r.Version.Type)
		constraints = append(constraints, r.Version.Constraint)
		require.NotNil(t, r.Fix)
		fixes = append(fixes, r.Fix.Version)
	}
	assert.Equal(t, []string{"<4.14.3", ">=5,<5.4.1"}, constraints)
	assert.Equal(t, []string{"4.14.3", "5.4.1"}, fixes)

	// the stored constraints are usable with the opam version format
	for _, tt := range []struct {
		version  string
		affected bool
	}{
		{version: "4.14.2", affected: true},
		{version: "4.14.3", affected: false},
		{version: "5.0.0~alpha1", affected: true}, // "5" < "5.0.0~alpha1" in opam ordering
		{version: "5.4.0", affected: true},
		{version: "5.4.1", affected: false},
	} {
		affected := false
		for _, r := range aph.BlobValue.Ranges {
			c, err := version.GetConstraint(r.Version.Constraint, version.ParseFormat(r.Version.Type))
			require.NoError(t, err)
			satisfied, err := c.Satisfied(version.New(tt.version, version.OpamFormat))
			require.NoError(t, err)
			affected = affected || satisfied
		}
		assert.Equal(t, tt.affected, affected, "version %s", tt.version)
	}
}

func TestOCamlTransformWithdrawn(t *testing.T) {
	vulns := loadFixture(t, "testdata/OSEC-2017-01.json")
	require.Len(t, vulns, 1)
	withdrawn := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	vulns[0].Withdrawn = withdrawn

	entries, err := Transform(vulns[0], inputProviderState())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	related, ok := entries[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)
	assert.Equal(t, db.VulnerabilityRejected, related.VulnerabilityHandle.Status)
	assert.Equal(t, &withdrawn, related.VulnerabilityHandle.WithdrawnDate)
}

func TestOCamlStrategyMatches(t *testing.T) {
	s := ocamlStrategy{}
	assert.True(t, s.Matches("OSEC-2026-01"))
	assert.False(t, s.Matches("GHSA-j26j-m5xr-g23c"))
	assert.False(t, s.Matches("CVE-2026-28364"))
}

// opam versions are not necessarily semver, e.g. menhir uses dates ("20260209")
// and Jane Street packages use a "v" prefix ("v0.16.0"); the constraint
// normalization must keep them intact.
func TestOCamlNonSemverRanges(t *testing.T) {
	tests := []struct {
		name       string
		introduced string
		fixed      string
		constraint string
		affected   []string
		unaffected []string
	}{
		{
			name:       "dates",
			introduced: "20220210",
			fixed:      "20260209",
			constraint: ">=20220210,<20260209",
			affected:   []string{"20220210", "20230415", "20260209~rc1"},
			unaffected: []string{"20211230", "20260209", "20260209.1"},
		},
		{
			name:       "v prefix",
			introduced: "v0.15.0",
			fixed:      "v0.16.0",
			constraint: ">=v0.15.0,<v0.16.0",
			affected:   []string{"v0.15.0", "v0.15.1", "v0.16.0~preview.129.00+243"},
			unaffected: []string{"v0.14.3", "v0.16.0", "v0.17.0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranges := eventsToRanges([]osvmodel.Event{{Introduced: tt.introduced}, {Fixed: tt.fixed}}, nil, "opam")
			require.Len(t, ranges, 1)
			assert.Equal(t, tt.constraint, ranges[0].Version.Constraint)
			require.NotNil(t, ranges[0].Fix)
			assert.Equal(t, tt.fixed, ranges[0].Fix.Version)

			c, err := version.GetConstraint(ranges[0].Version.Constraint, version.ParseFormat(ranges[0].Version.Type))
			require.NoError(t, err)
			for _, v := range tt.affected {
				satisfied, err := c.Satisfied(version.New(v, version.OpamFormat))
				require.NoError(t, err)
				assert.True(t, satisfied, "%s should be affected", v)
			}
			for _, v := range tt.unaffected {
				satisfied, err := c.Satisfied(version.New(v, version.OpamFormat))
				require.NoError(t, err)
				assert.False(t, satisfied, "%s should not be affected", v)
			}
		})
	}
}
