package match

import (
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
						Vulnerability: commonVulnerability,
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
			name: "does not merge matches with different fingerprints but semantically the same when matched by CPE",
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

func TestMatches_MergeSurvivorIsIndependentOfAddOrder(t *testing.T) {
	// Normalizing by CVE rewrites an ecosystem record's ID and namespace to the CVE it aliases, which
	// makes it collide with the NVD record for the same CVE and package. Only the identity is rewritten,
	// so the two matches share a fingerprint while still carrying the metadata and fix data of the
	// records they were found in. Whichever survives the merge is what a caller sees.
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "stdlib",
		Version: "go1.21.0",
		Type:    syftPkg.GoModulePkg,
	}

	// both records report the same fix versions, which is what puts them on the exact-fingerprint
	// merge path rather than the looser core-fingerprint one
	fixVersions := []string{"1.21.9", "1.22.2"}

	ecosystemMatch := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2023-45288", Namespace: "nvd:cpe"},
			Fix: vulnerability.Fix{
				Versions:  fixVersions,
				State:     vulnerability.FixStateFixed,
				Available: []vulnerability.FixAvailable{{Version: "1.21.9", Kind: "advisory"}},
			},
			Metadata: &vulnerability.Metadata{
				ID:         "CVE-2023-45288",
				Namespace:  "govulndb:language:go",
				DataSource: "https://go.dev/issue/65051",
			},
			RelatedVulnerabilities: []vulnerability.Reference{
				{ID: "GO-2024-2687", Namespace: "govulndb:language:go"},
			},
		},
		Package: p,
		Details: Details{{Type: ExactDirectMatch, Matcher: GoModuleMatcher, Confidence: 1}},
	}

	nvdMatch := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2023-45288", Namespace: "nvd:cpe"},
			Fix: vulnerability.Fix{
				Versions:  fixVersions,
				State:     vulnerability.FixStateFixed,
				Available: []vulnerability.FixAvailable{{Version: "1.21.9", Kind: "first-observed"}},
			},
			Metadata: &vulnerability.Metadata{
				ID:         "CVE-2023-45288",
				Namespace:  "nvd:cpe",
				DataSource: "https://nvd.nist.gov/vuln/detail/CVE-2023-45288",
			},
		},
		Package: p,
		Details: Details{{Type: CPEMatch, Matcher: GoModuleMatcher, Confidence: 0.9}},
	}

	require.Equal(t, ecosystemMatch.Fingerprint(), nvdMatch.Fingerprint(),
		"test requires both matches to collide on the exact fingerprint")

	tests := []struct {
		name  string
		added []Match
	}{
		{name: "ecosystem record added first", added: []Match{ecosystemMatch, nvdMatch}},
		{name: "nvd record added first", added: []Match{nvdMatch, ecosystemMatch}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := NewMatches(tt.added...)
			require.Equal(t, 1, matches.Count(), "expected the two records to merge into one match")

			actual := matches.Sorted()[0]

			require.NotNil(t, actual.Vulnerability.Metadata)
			assert.Equal(t, "https://go.dev/issue/65051", actual.Vulnerability.Metadata.DataSource)
			assert.Equal(t, "govulndb:language:go", actual.Vulnerability.Metadata.Namespace)
			require.Len(t, actual.Vulnerability.Fix.Available, 1)
			assert.Equal(t, "advisory", actual.Vulnerability.Fix.Available[0].Kind)

			// the merge should still union what both records contributed
			assert.ElementsMatch(t, []Type{ExactDirectMatch, CPEMatch}, actual.Details.Types())
			assert.Equal(t,
				[]vulnerability.Reference{{ID: "GO-2024-2687", Namespace: "govulndb:language:go"}},
				actual.Vulnerability.RelatedVulnerabilities)
		})
	}
}

func TestMatches_MergeKeepsTheIdentifiableRecord(t *testing.T) {
	// the provider leaves Vulnerability.Metadata nil when it cannot resolve metadata for a record, so
	// an equally-ranked record with no metadata must not displace one that has it
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "stdlib",
		Version: "go1.21.0",
		Type:    syftPkg.GoModulePkg,
	}
	newMatch := func(metadata *vulnerability.Metadata) Match {
		return Match{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{ID: "CVE-2023-45288", Namespace: "nvd:cpe"},
				Fix:       vulnerability.Fix{Versions: []string{"1.21.9"}},
				Metadata:  metadata,
			},
			Package: p,
			Details: Details{{Type: CPEMatch, Matcher: GoModuleMatcher, Confidence: 0.9}},
		}
	}

	identified := newMatch(&vulnerability.Metadata{
		ID:         "CVE-2023-45288",
		Namespace:  "nvd:cpe",
		DataSource: "https://nvd.nist.gov/vuln/detail/CVE-2023-45288",
	})
	unidentified := newMatch(nil)

	require.Equal(t, identified.Fingerprint(), unidentified.Fingerprint(),
		"test requires both matches to collide on the exact fingerprint")

	tests := []struct {
		name  string
		added []Match
	}{
		{name: "identified record added first", added: []Match{identified, unidentified}},
		{name: "unidentified record added first", added: []Match{unidentified, identified}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := NewMatches(tt.added...)
			require.Equal(t, 1, matches.Count())

			actual := matches.Sorted()[0]

			require.NotNil(t, actual.Vulnerability.Metadata, "the record with metadata should have survived")
			assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2023-45288", actual.Vulnerability.Metadata.DataSource)
		})
	}
}
