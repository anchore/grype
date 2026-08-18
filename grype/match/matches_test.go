package match

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatchesSortMixedDimensions(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0010",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	second := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0020",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-a",
			Version: "1.0.0",
			Type:    syftPkg.NpmPkg,
		},
	}
	third := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0020",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-a",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	fourth := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0020",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-c",
			Version: "3.0.0",
			Type:    syftPkg.ApkPkg,
		},
	}
	fifth := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0020",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-d",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	sixth := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0020",
			},
			Fix: vulnerability.Fix{
				Versions: []string{"2.0.0", "1.0.0"},
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-d",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	seventh := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0020",
			},
			Fix: vulnerability.Fix{
				Versions: []string{"2.0.1"},
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-d",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	eighth := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0020",
			},
			Fix: vulnerability.Fix{
				Versions: []string{"3.0.0"},
			},
		},
		Package: pkg.Package{
			ID:        pkg.ID(uuid.NewString()),
			Name:      "package-d",
			Version:   "2.0.0",
			Type:      syftPkg.RpmPkg,
			Locations: file.NewLocationSet(file.NewLocation("/some/first-path")),
		},
	}
	ninth := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0020",
			},
			Fix: vulnerability.Fix{
				Versions: []string{"3.0.0"},
			},
		},
		Package: pkg.Package{
			ID:        pkg.ID(uuid.NewString()),
			Name:      "package-d",
			Version:   "2.0.0",
			Type:      syftPkg.RpmPkg,
			Locations: file.NewLocationSet(file.NewLocation("/some/other-path")),
		},
	}

	input := []Match{
		// shuffle vulnerability id, package name, package version, and package type
		ninth, fifth, eighth, third, seventh, first, sixth, second, fourth,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second, third, fourth, fifth, sixth, seventh, eighth, ninth}, matches.Sorted())

}

func TestMatchesSortByVulnerability(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0010",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	second := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0020",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		second, first,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second}, matches.Sorted())

}

func TestMatches_AllByPkgID(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0010",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	second := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0010",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-c",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		second, first,
	}
	matches := NewMatches(input...)

	expected := map[pkg.ID][]Match{
		first.Package.ID: {
			first,
		},
		second.Package.ID: {
			second,
		},
	}

	assert.Equal(t, expected, matches.AllByPkgID())

}

func TestMatchesSortByPackage(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0010",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	second := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0010",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-c",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		second, first,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second}, matches.Sorted())

}

func TestMatchesSortByPackageVersion(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0010",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	second := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0010",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		second, first,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second}, matches.Sorted())

}

func TestMatchesSortByPackageType(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0010",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.ApkPkg,
		},
	}
	second := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2020-0010",
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		second, first,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second}, matches.Sorted())

}

func assertMatchOrder(t *testing.T, expected, actual []Match) {

	var expectedStr []string
	for _, e := range expected {
		expectedStr = append(expectedStr, e.Package.Name)
	}

	var actualStr []string
	for _, a := range actual {
		actualStr = append(actualStr, a.Package.Name)
	}

	// makes this easier on the eyes to sanity check...
	require.Equal(t, expectedStr, actualStr)

	// make certain the fields are what you'd expect
	assert.Equal(t, expected, actual)
}

func assertIgnoredMatchOrder(t *testing.T, expected, actual []IgnoredMatch) {

	var expectedStr []string
	for _, e := range expected {
		expectedStr = append(expectedStr, e.Package.Name)
	}

	var actualStr []string
	for _, a := range actual {
		actualStr = append(actualStr, a.Package.Name)
	}

	// makes this easier on the eyes to sanity check...
	require.Equal(t, expectedStr, actualStr)

	// make certain the fields are what you'd expect
	assert.Equal(t, expected, actual)
}

func TestMatches_Diff(t *testing.T) {
	a := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "vuln-a",
				Namespace: "name-a",
			},
		},
		Package: pkg.Package{
			ID: "package-a",
		},
	}

	b := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "vuln-b",
				Namespace: "name-b",
			},
		},
		Package: pkg.Package{
			ID: "package-b",
		},
	}

	c := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "vuln-c",
				Namespace: "name-c",
			},
		},
		Package: pkg.Package{
			ID: "package-c",
		},
	}

	tests := []struct {
		name    string
		subject Matches
		other   Matches
		want    Matches
	}{
		{
			name:    "no diff",
			subject: NewMatches(a, b, c),
			other:   NewMatches(a, b, c),
			want:    newMatches(),
		},
		{
			name:    "extra items in subject",
			subject: NewMatches(a, b, c),
			other:   NewMatches(a, b),
			want:    NewMatches(c),
		},
		{
			// this demonstrates that this is not meant to implement a symmetric diff
			name:    "extra items in other (results in no diff)",
			subject: NewMatches(a, b),
			other:   NewMatches(a, b, c),
			want:    NewMatches(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, &tt.want, tt.subject.Diff(tt.other), "Diff(%v)", tt.other)
		})
	}
}

func TestMatches_Add_Merge(t *testing.T) {
	commonVuln := "CVE-2023-0001"
	commonNamespace := "namespace1"
	commonVulnerability := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        commonVuln,
			Namespace: commonNamespace,
		},
		Constraint: func() version.Constraint {
			c, err := version.GetConstraint("< 1.0.0", version.SemanticFormat)
			require.NoError(t, err)
			return c
		}(),
		Fix: vulnerability.Fix{
			Versions: []string{"1.0.0"},
		},
	}

	commonDirectDetail := Detail{
		Type:       ExactDirectMatch,
		SearchedBy: "attr1",
		Found:      "value1",
		Matcher:    "matcher1",
	}

	matchPkg1Direct := Match{
		Vulnerability: commonVulnerability,
		Package: pkg.Package{
			ID: "pkg1",
		},
		Details: Details{
			commonDirectDetail,
		},
	}

	// several cases below pair the direct record above with a weaker record reporting a different
	// fixed-in version. The stronger record describes the merged finding, but neither fix is lost.
	commonVulnerabilityWithBothFixes := commonVulnerability
	commonVulnerabilityWithBothFixes.Fix = vulnerability.Fix{
		Versions: []string{"1.0.0", "3.2.12"},
	}

	matchPkg2Indirect := Match{
		Vulnerability: commonVulnerability,
		Package: pkg.Package{
			ID: "pkg2",
		},
		Details: Details{
			{
				Type:       ExactIndirectMatch,
				SearchedBy: "attr2",
				Found:      "value2",
				Matcher:    "matcher2",
			},
		},
	}

	tests := []struct {
		name            string
		matches         []Match
		expectedMatches map[string][]Match
	}{
		{
			name:    "adds new match without merging",
			matches: []Match{matchPkg1Direct, matchPkg2Indirect},
			expectedMatches: map[string][]Match{
				"pkg1": {
					matchPkg1Direct,
				},
				"pkg2": {
					matchPkg2Indirect,
				},
			},
		},
		{
			name: "merges matches with identical fingerprints",
			matches: []Match{
				matchPkg1Direct,
				{
					Vulnerability: matchPkg1Direct.Vulnerability,
					Package:       matchPkg1Direct.Package,
					Details: Details{
						{
							Type:       ExactIndirectMatch, // different!
							SearchedBy: "attr2",            // different!
							Found:      "value2",           // different!
							Matcher:    "matcher2",         // different!
						},
					},
				},
			},
			expectedMatches: map[string][]Match{
				"pkg1": {
					{
						Vulnerability: commonVulnerability,
						Package:       matchPkg1Direct.Package,
						Details: Details{
							commonDirectDetail,
							{
								Type:       ExactIndirectMatch,
								SearchedBy: "attr2",
								Found:      "value2",
								Matcher:    "matcher2",
							},
						},
					},
				},
			},
		},
		{
			name: "merges matches with different fingerprints but semantically the same",
			matches: []Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        commonVuln,
							Namespace: commonNamespace,
						},
						Constraint: func() version.Constraint { // different!
							c, err := version.GetConstraint("< 3.2.12", version.SemanticFormat)
							require.NoError(t, err)
							return c
						}(),
						Fix: vulnerability.Fix{
							Versions: []string{"3.2.12"}, // different!
						},
					},
					Package: matchPkg1Direct.Package,
					Details: Details{
						{
							Type:       ExactIndirectMatch, // different!
							SearchedBy: "attr1",
							Found:      "value1",
							Matcher:    "matcher1",
						},
					},
				},
				matchPkg1Direct,
			},
			expectedMatches: map[string][]Match{
				"pkg1": {
					{
						// the direct record describes the finding, but neither record's fixed-in
						// version is dropped
						Vulnerability: commonVulnerabilityWithBothFixes,
						Package:       matchPkg1Direct.Package,
						Details: Details{
							commonDirectDetail, // sorts to first (direct should be prioritized over indirect)
							{
								Type:       ExactIndirectMatch, // different!
								SearchedBy: "attr1",
								Found:      "value1",
								Matcher:    "matcher1",
							},
						},
					},
				},
			},
		},
		{
			// a CVE from one source reached both by CPE and by a direct match on the same package is
			// one finding, not two -- this is the NVD shape where one CVE lists several vulnerable
			// CPEs, each its own record with its own fixed-in version
			name: "merges a CPE match into a direct match for the same finding",
			matches: []Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        commonVuln,
							Namespace: commonNamespace,
						},
						Constraint: func() version.Constraint { // different!
							c, err := version.GetConstraint("< 3.2.12", version.SemanticFormat)
							require.NoError(t, err)
							return c
						}(),
						Fix: vulnerability.Fix{
							Versions: []string{"3.2.12"}, // different!
						},
					},
					Package: matchPkg1Direct.Package,
					Details: Details{
						{
							Type:       CPEMatch, // different!
							SearchedBy: "attr1",
							Found:      "value1",
							Matcher:    "matcher1",
						},
					},
				},
				matchPkg1Direct,
			},
			expectedMatches: map[string][]Match{
				"pkg1": {
					{
						// the direct match is the stronger record, so it describes the finding
						Vulnerability: commonVulnerabilityWithBothFixes,
						Package:       matchPkg1Direct.Package,
						Details: Details{
							commonDirectDetail, // sorts to first (direct should be prioritized over CPE)
							{
								Type:       CPEMatch,
								SearchedBy: "attr1",
								Found:      "value1",
								Matcher:    "matcher1",
							},
						},
					},
				},
			},
		},
	}

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(vulnerability.Vulnerability{}, pkg.Package{}, file.Location{}, file.LocationSet{}),
		cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
		cmpopts.EquateEmpty(),
		cmpopts.SortSlices(func(a, b Match) bool {
			return ByElements([]Match{a, b}).Less(0, 1)
		}),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := NewMatches(tt.matches...)

			require.NotEmpty(t, tt.expectedMatches)

			for pkgId, expected := range tt.expectedMatches {
				storedMatches := actual.GetByPkgID(pkg.ID(pkgId))

				if d := cmp.Diff(expected, storedMatches, cmpOpts...); d != "" {
					t.Errorf("unexpected matches for %q (-want, +got): %s", pkgId, d)
				}
			}

			assert.Len(t, actual.byPackage, len(tt.expectedMatches))

		})
	}
}

// TestMatches_Add_CollapsesRecordsIntoOneFinding pins the shape of the fingerprint: one
// vulnerability, from one source, on one package is one finding, however many database records
// produced it and however much they disagree about the fixed-in version.
//
// This also covers a pair of bugs in the two-tier index this replaced: the "indirect merges into an
// existing direct match" rule was dead code (it routed through Match.Merge, which rejected the very
// records it was handed), so the finding count depended on which order the matcher happened to emit
// its records -- indirect-then-direct collapsed to one match, direct-then-indirect did not.
func TestMatches_Add_CollapsesRecordsIntoOneFinding(t *testing.T) {
	mk := func(fix string, ty Type) Match {
		return Match{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{ID: "CVE-2023-0001", Namespace: "namespace1"},
				Fix:       vulnerability.Fix{Versions: []string{fix}},
			},
			Package: pkg.Package{ID: "pkg1"},
			// searched-by varies per record so each contributes a distinct detail
			Details: Details{{Type: ty, SearchedBy: string(ty), Found: "value", Matcher: "matcher"}},
		}
	}

	tests := []struct {
		name string
		// the strongest record's match type, which describes the merged finding
		matches []Match
	}{
		{
			name:    "indirect then direct",
			matches: []Match{mk("3.2.12", ExactIndirectMatch), mk("1.0.0", ExactDirectMatch)},
		},
		{
			// the mirror of the above: used to yield two findings, because case B2 never fired
			name:    "direct then indirect",
			matches: []Match{mk("1.0.0", ExactDirectMatch), mk("3.2.12", ExactIndirectMatch)},
		},
		{
			name:    "CPE then direct",
			matches: []Match{mk("3.2.12", CPEMatch), mk("1.0.0", ExactDirectMatch)},
		},
		{
			name:    "direct then CPE",
			matches: []Match{mk("1.0.0", ExactDirectMatch), mk("3.2.12", CPEMatch)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMatches(tt.matches...)

			matches := m.Sorted()
			require.Len(t, matches, 1, "expected the records to collapse into a single finding")
			require.Equal(t, 1, m.Count())
			got := matches[0]

			// neither record's fix is lost
			assert.Equal(t, []string{"1.0.0", "3.2.12"}, got.Vulnerability.Fix.Versions)

			// every record still says how it matched, and the strongest sorts first regardless of
			// arrival order
			assert.Equal(t, ExactDirectMatch, got.Details.Types()[0])
			assert.ElementsMatch(t,
				[]Type{tt.matches[0].Details[0].Type, tt.matches[1].Details[0].Type},
				got.Details.Types())

			// the package index resolves to the live match
			for fp := range m.byPackage["pkg1"] {
				require.Contains(t, m.byFingerprint, fp,
					"byPackage[pkg1] tracks a fingerprint with no match: %s", fp)
			}
		})
	}
}

// TestMatches_Add_KeepsSeparateSources guards the other side of the fingerprint: records from
// different sources are not merged, so a distro advisory's fixed-in version can never end up in the
// same list as an upstream one (they use different version schemes).
func TestMatches_Add_KeepsSeparateSources(t *testing.T) {
	mk := func(namespace, fix string, ty Type) Match {
		return Match{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{ID: "CVE-2018-0735", Namespace: namespace},
				Fix:       vulnerability.Fix{Versions: []string{fix}},
			},
			Package: pkg.Package{ID: "pkg1"},
			Details: Details{{Type: ty, SearchedBy: namespace, Found: "value", Matcher: "matcher"}},
		}
	}

	m := NewMatches(
		mk("redhat:distro:redhat:7", "1:1.0.2k-16.el7_6.1", ExactDirectMatch),
		mk("nvd:cpe", "1.1.0i", CPEMatch),
	)

	matches := m.Sorted()
	require.Len(t, matches, 2, "records from different sources should stay separate findings")
	for _, got := range matches {
		require.Len(t, got.Vulnerability.Fix.Versions, 1,
			"fixed-in versions from different sources must not be unioned: %v", got.Vulnerability.Fix.Versions)
	}
}

// BenchmarkMatchesAddOneFinding tracks the cost of building a single finding out of N database records.
func BenchmarkMatchesAddOneFinding(b *testing.B) {
	for _, n := range []int{2, 10, 50} {
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				matches := NewMatches()
				for j := 0; j < n; j++ {
					matches.Add(Match{
						Vulnerability: vulnerability.Vulnerability{
							Reference: vulnerability.Reference{ID: "CVE-2026-1", Namespace: "nvd:cpe"},
							Fix:       vulnerability.Fix{Versions: []string{fmt.Sprintf("%d.0.0", j)}},
						},
						Package: pkg.Package{ID: "pkg1", Name: "widget", Version: "1.5.0"},
						Details: Details{benchmarkCPEDetail(j)},
					})
				}
			}
		})
	}
}
