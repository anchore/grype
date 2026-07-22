package csaf

import (
	"slices"
	"testing"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	vexStatus "github.com/anchore/grype/grype/vex/status"
	"github.com/anchore/grype/grype/vulnerability"
)

func Test_newerCurrentReleaseDateFirst(t *testing.T) {
	type dateIDPair struct {
		date string
		id   string
	}

	tests := []struct {
		name     string
		input    []dateIDPair
		expected []string
	}{
		{
			name: "simple sort newest first",
			input: []dateIDPair{
				{"2023-01-01T00:00:00Z", "doc1"},
				{"2024-01-01T00:00:00Z", "doc2"},
				{"2022-01-01T00:00:00Z", "doc3"},
			},
			expected: []string{"doc2", "doc1", "doc3"},
		},
		{
			name: "already sorted",
			input: []dateIDPair{
				{"2024-01-01T00:00:00Z", "doc1"},
				{"2023-01-01T00:00:00Z", "doc2"},
			},
			expected: []string{"doc1", "doc2"},
		},
		{
			name: "same dates maintain order",
			input: []dateIDPair{
				{"2023-01-01T00:00:00Z", "first"},
				{"2023-01-01T00:00:00Z", "second"},
			},
			expected: []string{"first", "second"},
		},
		{
			name: "nil dates go last",
			input: []dateIDPair{
				{"", "nil1"},
				{"2023-01-01T00:00:00Z", "valid1"},
				{"2024-01-01T00:00:00Z", "valid2"},
			},
			expected: []string{"valid2", "valid1", "nil1"},
		},
		{
			name: "multiple nils maintain order",
			input: []dateIDPair{
				{"", "nil1"},
				{"2023-01-01T00:00:00Z", "valid"},
				{"", "nil2"},
			},
			expected: []string{"valid", "nil1", "nil2"},
		},
		{
			name: "all nils",
			input: []dateIDPair{
				{"", "first"},
				{"", "second"},
				{"", "third"},
			},
			expected: []string{"first", "second", "third"},
		},
		{
			name: "invalid date format goes last",
			input: []dateIDPair{
				{"invalid-date", "bad"},
				{"2023-01-01T00:00:00Z", "good"},
			},
			expected: []string{"good", "bad"},
		},
		{
			name: "mix of nil invalid and valid",
			input: []dateIDPair{
				{"", "nil"},
				{"invalid", "bad"},
				{"2024-01-01T00:00:00Z", "new"},
				{"2023-01-01T00:00:00Z", "old"},
			},
			expected: []string{"new", "old", "nil", "bad"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advs := make(advisories, len(tt.input))
			for i, pair := range tt.input {
				var datePtr *string
				if pair.date == "" {
					datePtr = nil
				} else {
					datePtr = &pair.date
				}

				advs[i] = &csaf.Advisory{
					Document: &csaf.Document{
						Tracking: &csaf.Tracking{
							ID:                 (*csaf.TrackingID)(&pair.id),
							CurrentReleaseDate: datePtr,
						},
					},
				}
			}

			slices.SortStableFunc(advs, newerCurrentReleaseDateFirst)

			result := make([]string, len(advs))
			for i, adv := range advs {
				result[i] = string(*adv.Document.Tracking.ID)
			}

			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_matchingRule(t *testing.T) {
	tests := []struct {
		name            string
		ignoreRules     []match.IgnoreRule
		m               match.Match
		advMatch        *advisoryMatch
		allowedStatuses []vexStatus.Status
		expected        *match.IgnoreRule
	}{
		{
			name:        "no ignore rules, not_affected status with inline mitigations",
			ignoreRules: []match.IgnoreRule{}, // No existing ignore rules
			m: match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{ID: "CVE-2023-1234"},
				},
				Package: pkg.Package{Name: "test-package"},
			},
			advMatch: &advisoryMatch{
				Vulnerability: &csaf.Vulnerability{
					CVE: func() *csaf.CVE { cve := csaf.CVE("CVE-2023-1234"); return &cve }(),
				},
				Status:    knownNotAffected, // CSAF status
				ProductID: "test-product-1",
			},
			allowedStatuses: vexStatus.IgnoreList(), // [Fixed, NotAffected]
			expected: &match.IgnoreRule{
				Namespace:        "vex",
				Vulnerability:    "CVE-2023-1234",
				VexJustification: "", // Will be empty since no flags/threats in this simple case
				VexStatus:        "not_affected",
			},
		},
		{
			name:        "no ignore rules, under_investigation status should return nil",
			ignoreRules: []match.IgnoreRule{}, // No existing ignore rules
			m: match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{ID: "CVE-2023-5678"},
				},
				Package: pkg.Package{Name: "another-package"},
			},
			advMatch: &advisoryMatch{
				Vulnerability: &csaf.Vulnerability{
					CVE: func() *csaf.CVE { cve := csaf.CVE("CVE-2023-5678"); return &cve }(),
				},
				Status:    underInvestigation, // CSAF status
				ProductID: "test-product-2",
			},
			allowedStatuses: vexStatus.IgnoreList(), // [Fixed, NotAffected] - doesn't include UnderInvestigation
			expected:        nil,                    // Should return nil since under_investigation is not in allowed statuses
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchingRule(tt.ignoreRules, tt.m, tt.advMatch, tt.allowedStatuses)
			if tt.expected == nil {
				require.Nil(t, result)
				return
			}
			if d := cmp.Diff(*result, *tt.expected); d != "" {
				t.Errorf("mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestPackageMatchesStatement(t *testing.T) {
	mkPkg := func(purl string) *pkg.Package {
		return &pkg.Package{
			Type: "go-module",
			PURL: purl,
		}
	}

	tests := []struct {
		name     string
		stmtPURL string
		pkgPURL  string
		status   status
		want     bool
	}{
		// last_affected: ceiling
		{"last_affected matches lower pkg version", "pkg:golang/golang.org/x/net@v0.54.0", "pkg:golang/golang.org/x/net@v0.53.0", lastAffected, true},
		{"last_affected matches equal pkg version", "pkg:golang/golang.org/x/net@v0.53.0", "pkg:golang/golang.org/x/net@v0.53.0", lastAffected, true},
		{"last_affected excludes higher pkg version", "pkg:golang/golang.org/x/net@v0.53.0", "pkg:golang/golang.org/x/net@v0.54.0", lastAffected, false},

		// first_affected: floor
		{"first_affected matches higher pkg version", "pkg:golang/golang.org/x/net@v0.50.0", "pkg:golang/golang.org/x/net@v0.53.0", firstAffected, true},
		{"first_affected matches equal pkg version", "pkg:golang/golang.org/x/net@v0.53.0", "pkg:golang/golang.org/x/net@v0.53.0", firstAffected, true},
		{"first_affected excludes lower pkg version", "pkg:golang/golang.org/x/net@v0.53.0", "pkg:golang/golang.org/x/net@v0.50.0", firstAffected, false},

		// known_affected, recommended, under_investigation: exact
		{"known_affected matches equal", "pkg:golang/golang.org/x/net@v0.53.0", "pkg:golang/golang.org/x/net@v0.53.0", knownAffected, true},
		{"known_affected excludes lower", "pkg:golang/golang.org/x/net@v0.53.0", "pkg:golang/golang.org/x/net@v0.52.0", knownAffected, false},
		{"recommended excludes lower", "pkg:golang/golang.org/x/net@v0.53.0", "pkg:golang/golang.org/x/net@v0.52.0", recommended, false},
		{"under_investigation matches equal", "pkg:golang/golang.org/x/net@v0.53.0", "pkg:golang/golang.org/x/net@v0.53.0", underInvestigation, true},
		{"under_investigation excludes lower", "pkg:golang/golang.org/x/net@v0.53.0", "pkg:golang/golang.org/x/net@v0.52.0", underInvestigation, false},

		// wildcard (no statement version) matches any version regardless of status
		{"wildcard last_affected matches any", "pkg:golang/golang.org/x/net", "pkg:golang/golang.org/x/net@v0.99.0", lastAffected, true},
		{"wildcard known_affected matches any", "pkg:golang/golang.org/x/net", "pkg:golang/golang.org/x/net@v0.99.0", knownAffected, true},

		// name / namespace / type mismatches
		{"name mismatch excludes", "pkg:golang/golang.org/x/net@v0.53.0", "pkg:golang/golang.org/x/text@v0.53.0", lastAffected, false},
		{"namespace mismatch excludes", "pkg:golang/golang.org/x/net@v0.53.0", "pkg:golang/example.com/x/net@v0.53.0", lastAffected, false},
		{"type mismatch excludes", "pkg:golang/golang.org/x/net@v0.53.0", "pkg:npm/x-net@v0.53.0", lastAffected, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := packageMatchesStatement(tt.stmtPURL, mkPkg(tt.pkgPURL), tt.status)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestAugmentMatches_SynthesizesFromPackageCatalog(t *testing.T) {
	const (
		vulnID  = "CVE-2099-0001"
		basePkg = "pkg:golang/golang.org/x/net@v0.53.0"
	)

	xNet := pkg.Package{
		ID:      "deadbeefcafebabe",
		Name:    "golang.org/x/net",
		Version: "v0.53.0",
		Type:    "go-module",
		PURL:    basePkg,
	}

	mkAdv := func(stmtPURL string, statusKey status) *csaf.Advisory {
		productID := csaf.ProductID("test-pkg")
		cve := csaf.CVE(vulnID)
		pvCat := csaf.CSAFBranchCategoryProductVersion
		pvName := "1.0"
		pnCat := csaf.CSAFBranchCategoryProductName
		pnName := "Test"
		productBranch := &csaf.Branch{
			Category: &pvCat,
			Name:     &pvName,
			Product: &csaf.FullProductName{
				Name:      &[]string{"test"}[0],
				ProductID: &productID,
				ProductIdentificationHelper: &csaf.ProductIdentificationHelper{
					PURL: &[]csaf.PURL{csaf.PURL(stmtPURL)}[0],
				},
			},
		}
		rootBranch := &csaf.Branch{
			Category: &pnCat,
			Name:     &pnName,
			Branches: csaf.Branches{productBranch},
		}

		ps := csaf.ProductStatus{}
		products := csaf.Products{&productID}
		switch statusKey {
		case lastAffected:
			ps.LastAffected = &products
		case firstAffected:
			ps.FirstAffected = &products
		case knownAffected:
			ps.KnownAffected = &products
		case recommended:
			ps.Recommended = &products
		case underInvestigation:
			ps.UnderInvestigation = &products
		case fixed:
			ps.Fixed = &products
		case knownNotAffected:
			ps.KnownNotAffected = &products
		}

		return &csaf.Advisory{
			ProductTree: &csaf.ProductTree{
				Branches: csaf.Branches{rootBranch},
			},
			Vulnerabilities: []*csaf.Vulnerability{{
				CVE:           &cve,
				ProductStatus: &ps,
				Title:         &[]string{"test"}[0],
			}},
		}
	}

	tests := []struct {
		name      string
		stmtPURL  string
		stmtStat  status
		pkgs      []pkg.Package
		wantSynth bool
	}{
		// last_affected: ceiling
		{"last_affected synthesizes for lower pkg", "pkg:golang/golang.org/x/net@v0.55.0", lastAffected, []pkg.Package{xNet}, true},
		{"last_affected synthesizes for equal pkg", "pkg:golang/golang.org/x/net@v0.53.0", lastAffected, []pkg.Package{xNet}, true},
		{"last_affected skips for higher pkg", "pkg:golang/golang.org/x/net@v0.50.0", lastAffected, []pkg.Package{xNet}, false},

		// first_affected: floor
		{"first_affected synthesizes for higher pkg", "pkg:golang/golang.org/x/net@v0.50.0", firstAffected, []pkg.Package{xNet}, true},
		{"first_affected skips for lower pkg", "pkg:golang/golang.org/x/net@v0.99.0", firstAffected, []pkg.Package{xNet}, false},

		// known_affected: exact
		{"known_affected synthesizes for equal pkg", "pkg:golang/golang.org/x/net@v0.53.0", knownAffected, []pkg.Package{xNet}, true},
		{"known_affected skips for lower pkg", "pkg:golang/golang.org/x/net@v0.55.0", knownAffected, []pkg.Package{xNet}, false},

		// fixed/known_not_affected: must not synthesize
		{"fixed does not synthesize", "pkg:golang/golang.org/x/net@v0.53.0", fixed, []pkg.Package{xNet}, false},
		{"known_not_affected does not synthesize", "pkg:golang/golang.org/x/net@v0.53.0", knownNotAffected, []pkg.Package{xNet}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advs := advisories{mkAdv(tt.stmtPURL, tt.stmtStat)}
			matches := match.NewMatches()

			processor := &Processor{}
			out, _, err := processor.AugmentMatches(advs, nil, nil, tt.pkgs, &matches, nil)
			require.NoError(t, err)

			if tt.wantSynth {
				require.Len(t, out.Sorted(), 1, "expected one synthesized match")
				got := out.Sorted()[0]
				require.Equal(t, vulnID, got.Vulnerability.ID)
				require.Equal(t, xNet.PURL, got.Package.PURL)
			} else {
				require.Empty(t, out.Sorted(), "did not expect a synthesized match")
			}
		})
	}
}

func TestAugmentMatches_DoesNotDuplicateExistingMatches_CSAF(t *testing.T) {
	const vulnID = "CVE-2099-0002"
	p := pkg.Package{
		Name: "example.com/foo",
		PURL: "pkg:golang/example.com/foo@v1.0.0",
		Type: "go-module",
	}

	existing := match.Match{
		Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: vulnID}},
		Package:       p,
	}

	productID := csaf.ProductID("p1")
	cve := csaf.CVE(vulnID)
	fullProductName := &csaf.FullProductName{
		Name:      &[]string{"foo"}[0],
		ProductID: &productID,
		ProductIdentificationHelper: &csaf.ProductIdentificationHelper{
			PURL: &[]csaf.PURL{csaf.PURL(p.PURL)}[0],
		},
	}
	pvCat := csaf.CSAFBranchCategoryProductVersion
	pvName := "1.0.0"
	pnCat := csaf.CSAFBranchCategoryProductName
	pnName := "Foo"
	productBranch := &csaf.Branch{Category: &pvCat, Name: &pvName, Product: fullProductName}
	rootBranch := &csaf.Branch{Category: &pnCat, Name: &pnName, Branches: csaf.Branches{productBranch}}
	products := csaf.Products{&productID}
	advs := advisories{&csaf.Advisory{
		ProductTree: &csaf.ProductTree{Branches: csaf.Branches{rootBranch}},
		Vulnerabilities: []*csaf.Vulnerability{{
			CVE:           &cve,
			ProductStatus: &csaf.ProductStatus{LastAffected: &products},
			Title:         &[]string{"t"}[0],
		}},
	}}

	matches := match.NewMatches(existing)

	processor := &Processor{}
	out, _, err := processor.AugmentMatches(advs, nil, nil, []pkg.Package{p}, &matches, nil)
	require.NoError(t, err)

	require.Len(t, out.Sorted(), 1, "synthesis must dedupe against existing matches")
	// Use slices so we don't accidentally accept additional unrelated matches.
	require.True(t, slices.ContainsFunc(out.Sorted(), func(m match.Match) bool {
		return m.Vulnerability.ID == vulnID && m.Package.PURL == p.PURL
	}))
}
