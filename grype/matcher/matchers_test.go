package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
)

func TestApplySelectionPolicy_UsesDefaultOSMatchersForNonRapidFortSources(t *testing.T) {
	matchers := ApplySelectionPolicy(NewDefaultMatchers(Config{}), pkg.Context{})

	assert.Contains(t, matcherTypes(matchers), match.DpkgMatcher)
	assert.Contains(t, matcherTypes(matchers), match.ApkMatcher)
	assert.NotContains(t, matcherTypes(matchers), match.RapidFortMatcher)
}

func TestApplySelectionPolicy_UsesDefaultOSMatchersWhenMarkerFileAbsent(t *testing.T) {
	// IsRapidFortImage=false is the state set by the package providers when the
	// RapidFort curation marker file is not present in the image or SBOM.
	matchers := ApplySelectionPolicy(NewDefaultMatchers(Config{}), pkg.Context{
		IsRapidFortImage: false,
	})

	assert.Contains(t, matcherTypes(matchers), match.DpkgMatcher)
	assert.Contains(t, matcherTypes(matchers), match.ApkMatcher)
	assert.NotContains(t, matcherTypes(matchers), match.RapidFortMatcher)
}

func TestApplySelectionPolicy_UsesRapidFortMatcherWhenMarkerFilePresent(t *testing.T) {
	// IsRapidFortImage=true is the state set by the package providers when the
	// RapidFort curation marker file (pkg.RapidFortMarkerPath) exists in the
	// scanned image or SBOM catalog.
	matchers := ApplySelectionPolicy(NewDefaultMatchers(Config{}), pkg.Context{
		IsRapidFortImage: true,
	})

	assert.Contains(t, matcherTypes(matchers), match.RapidFortMatcher)
	assert.NotContains(t, matcherTypes(matchers), match.DpkgMatcher)
	assert.NotContains(t, matcherTypes(matchers), match.ApkMatcher)
	assert.NotContains(t, matcherTypes(matchers), match.RpmMatcher)
	assert.Contains(t, matcherTypes(matchers), match.JavaMatcher)
	assert.Contains(t, matcherTypes(matchers), match.StockMatcher)
}

func matcherTypes(matchers []match.Matcher) []match.MatcherType {
	out := make([]match.MatcherType, 0, len(matchers))
	for _, m := range matchers {
		out = append(out, m.Type())
	}
	return out
}
