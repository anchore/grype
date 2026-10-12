package result

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// fixedRewrites rewrites every search to the same criteria, recording what it was asked about.
type fixedRewrites struct {
	vulnerability.Provider
	rewrite func(cs []vulnerability.Criteria) [][]vulnerability.Criteria
	asked   *[]pkg.Package
}

var _ v6.SearchRuleProvider = fixedRewrites{}

func (p fixedRewrites) SearchRewrites(catalogedPkg pkg.Package, cs []vulnerability.Criteria) ([][]vulnerability.Criteria, bool) {
	*p.asked = append(*p.asked, catalogedPkg)
	return p.rewrite(cs), true
}

func TestSearchRewrites_ProviderWithoutRulesSearchesAsIs(t *testing.T) {
	searches, rewritten := searchRewrites(mock.VulnerabilityProvider(), pkg.Package{}, []vulnerability.Criteria{search.ByPackageName("curl")})
	assert.False(t, rewritten)
	assert.Nil(t, searches)
}

func TestProvider_RanksBySearchRule(t *testing.T) {
	p := pkg.Package{Name: "curl", Version: "1.0", Type: syftPkg.ApkPkg}
	vuln := func(id, name string) vulnerability.Vulnerability {
		return vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: id, Namespace: "ns"}, PackageName: name}
	}

	var asked []pkg.Package
	vp := fixedRewrites{
		Provider: mock.VulnerabilityProvider(vuln("CVE-1", "curl"), vuln("CVE-2", "rf-curl"), vuln("CVE-3", "fips-curl")),
		asked:    &asked,
		rewrite: func(cs []vulnerability.Criteria) [][]vulnerability.Criteria {
			return [][]vulnerability.Criteria{
				cs,
				{search.ByPackageName("rf-curl"), search.ByRule(30)},
				{search.ByPackageName("fips-curl"), search.ByRule(-5)},
			}
		},
	}

	got, err := NewProvider(vp, p, match.ApkMatcher).FindResults(search.ByPackageName("curl"))
	require.NoError(t, err)

	require.Equal(t, []pkg.Package{p}, asked, "the rules are asked about the cataloged package")

	rankOfID := func(id string) Rank {
		require.Len(t, got[id], 1, id)
		return got[id][0].Rank
	}
	assert.Equal(t, Rank{}, rankOfID("CVE-1"))
	assert.Equal(t, Rank{FromSearchRule: true, RulePriority: 30}, rankOfID("CVE-2"))
	assert.Equal(t, Rank{FromSearchRule: true, RulePriority: -5}, rankOfID("CVE-3"))
	assert.Positive(t, rankOfID("CVE-3").Compare(rankOfID("CVE-1")), "any rule outranks the package's own rows")
}

func TestProvider_RewriteToNothingSearchesNothing(t *testing.T) {
	var asked []pkg.Package
	vp := fixedRewrites{
		Provider: mock.VulnerabilityProvider(vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-1"}, PackageName: "curl"}),
		asked:    &asked,
		rewrite:  func([]vulnerability.Criteria) [][]vulnerability.Criteria { return nil },
	}
	got, err := NewProvider(vp, pkg.Package{Name: "curl"}, match.ApkMatcher).FindResults(search.ByPackageName("curl"))
	require.NoError(t, err)
	assert.Empty(t, got)
}
