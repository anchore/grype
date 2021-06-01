package common

import (
	"fmt"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/stretchr/testify/assert"

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
				Constraint: version.MustGetConstraint("< 3.7.6", version.SemanticFormat),
				ID:         "CVE-2017-fake-1",
				Namespace:  "github:ruby",
			},
			{
				Constraint: version.MustGetConstraint("< 3.7.4", version.SemanticFormat),
				ID:         "CVE-2017-fake-2",
				Namespace:  "github:ruby",
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

func TestFindMatchesByPackageLanguage(t *testing.T) {
	p := pkg.Package{
		Name:     "activerecord",
		Version:  "3.7.5",
		Language: syftPkg.Ruby,
		Type:     syftPkg.GemPkg,
	}

	expected := []match.Match{
		{
			Type: match.ExactDirectMatch,
			Vulnerability: vulnerability.Vulnerability{
				ID: "CVE-2017-fake-1",
			},
			Package: p,
			MatchDetails: []match.Details{
				{
					Confidence: 1,
					SearchedBy: map[string]interface{}{
						"language":  "ruby",
						"namespace": "github:ruby",
					},
					Found: map[string]interface{}{
						"versionConstraint": "< 3.7.6 (semver)",
					},
					Matcher: match.RubyGemMatcher,
				},
			},
		},
	}

	store := newMockProviderByLanguage()
	actual, err := FindMatchesByPackageLanguage(store, p.Language, p, match.RubyGemMatcher)
	assert.NoError(t, err)
	assertMatchesUsingIDsForVulnerabilities(t, expected, actual)
}
