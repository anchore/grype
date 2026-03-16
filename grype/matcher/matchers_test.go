package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestApplySelectionPolicy_UsesDefaultOSMatchersForNonRapidFortSources(t *testing.T) {
	matchers := ApplySelectionPolicy(NewDefaultMatchers(Config{}), pkg.Context{})

	assert.Contains(t, matcherTypes(matchers), match.DpkgMatcher)
	assert.Contains(t, matcherTypes(matchers), match.ApkMatcher)
	assert.NotContains(t, matcherTypes(matchers), match.RapidFortMatcher)
}

func TestApplySelectionPolicy_UsesDefaultOSMatchersForNonRapidFortImage(t *testing.T) {
	matchers := ApplySelectionPolicy(NewDefaultMatchers(Config{}), pkg.Context{
		Source: &source.Description{
			Metadata: source.ImageMetadata{
				Labels: map[string]string{
					"maintainer": "Other Vendor <other@example.com>",
				},
			},
		},
	})

	assert.Contains(t, matcherTypes(matchers), match.DpkgMatcher)
	assert.Contains(t, matcherTypes(matchers), match.ApkMatcher)
	assert.NotContains(t, matcherTypes(matchers), match.RapidFortMatcher)
}

func TestApplySelectionPolicy_UsesRapidFortMatcherInsteadOfDebAndApkMatchers(t *testing.T) {
	matchers := ApplySelectionPolicy(NewDefaultMatchers(Config{}), pkg.Context{
		Source: &source.Description{
			Metadata: source.ImageMetadata{
				Labels: map[string]string{
					"maintainer": "RapidFort Curation Team <rfcurators@rapidfort.com>",
				},
			},
		},
	})

	assert.Contains(t, matcherTypes(matchers), match.RapidFortMatcher)
	assert.NotContains(t, matcherTypes(matchers), match.DpkgMatcher)
	assert.NotContains(t, matcherTypes(matchers), match.ApkMatcher)
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
