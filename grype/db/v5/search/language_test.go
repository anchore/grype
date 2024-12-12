package search

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type mockLanguageProvider struct {
	data map[string]map[string][]vulnerability.Vulnerability
}

func newMockProviderByLanguage() *mockLanguageProvider {
	pr := mockLanguageProvider{
		data: make(map[string]map[string][]vulnerability.Vulnerability),
	}
	pr.stub()
	return &pr
}

func (pr *mockLanguageProvider) stub() {
	pr.data["github:gem"] = map[string][]vulnerability.Vulnerability{
		// direct...
		"activerecord": {
			{
				// make sure we find it with semVer constraint
				Constraint: version.MustGetConstraint("< 3.7.6", version.SemanticFormat),
				Reference: vulnerability.Reference{
					ID:        "CVE-2017-fake-1",
					Namespace: "github:ruby",
				},
			},
			{
				Constraint: version.MustGetConstraint("< 3.7.4", version.GemFormat),
				Reference: vulnerability.Reference{
					ID:        "CVE-2017-fake-2",
					Namespace: "github:ruby",
				},
			},
		},
		"nokogiri": {
			{
				// make sure we find it with gem version constraint
				Constraint: version.MustGetConstraint("< 1.7.6", version.GemFormat),
				Reference: vulnerability.Reference{
					ID:        "CVE-2017-fake-1",
					Namespace: "github:ruby",
				},
			},
			{
				Constraint: version.MustGetConstraint("< 1.7.4", version.SemanticFormat),
				Reference: vulnerability.Reference{
					ID:        "CVE-2017-fake-2",
					Namespace: "github:ruby",
				},
			},
		},
	}
}

func (pr *mockLanguageProvider) GetByLanguage(l syftPkg.Language, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	if l != syftPkg.Ruby {
		panic(fmt.Errorf("test mock only supports ruby"))
	}
	return pr.data["github:gem"][p.Name], nil
}

func expectedMatch(p pkg.Package, constraint string) []match.Match {
	return []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2017-fake-1",
				},
			},
			Package: p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1,
					SearchedBy: map[string]interface{}{
						"language":  "ruby",
						"namespace": "github:ruby",
						"package":   map[string]string{"name": p.Name, "version": p.Version},
					},
					Found: map[string]interface{}{
						"versionConstraint": constraint,
						"vulnerabilityID":   "CVE-2017-fake-1",
					},
					Matcher: match.RubyGemMatcher,
				},
			},
		},
	}
}

func TestFindMatchesByPackageLanguage(t *testing.T) {
	cases := []struct {
		p           pkg.Package
		constraint  string
		assertEmpty bool
	}{
		{
			constraint: "< 3.7.6 (semver)",
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "activerecord",
				Version:  "3.7.5",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
		},
		{
			constraint: "< 1.7.6 (semver)",
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "nokogiri",
				Version:  "1.7.5",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
		},
		{
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "nokogiri",
				Version:  "unknown",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			assertEmpty: true,
		},
	}

	store := newMockProviderByLanguage()
	for _, c := range cases {
		t.Run(c.p.Name, func(t *testing.T) {
			actual, err := ByPackageLanguage(store, nil, c.p, match.RubyGemMatcher)
			require.NoError(t, err)
			if c.assertEmpty {
				assert.Empty(t, actual)
				return
			}
			assertMatchesUsingIDsForVulnerabilities(t, expectedMatch(c.p, c.constraint), actual)
		})
	}
}
