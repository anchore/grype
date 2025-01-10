package internal

import (
	"slices"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

type MatcherAdapter struct {
	Matcher TypedMatcher
}

func (m MatcherAdapter) Type() match.MatcherType {
	return m.Matcher.Type()
}

func (m MatcherAdapter) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoredMatch, error) {
	if !slices.Contains(m.Matcher.PackageTypes(), p.Type) {
		return nil, nil, match.ErrUnsupportedPackageType
	}
	return m.Matcher.Match(store, p)
}

var _ match.Matcher = (*MatcherAdapter)(nil)
