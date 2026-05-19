package pacman

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct{}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.AlpmPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.PacmanMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	matches, ignoreFilters, err := internal.MatchPackageByDistro(store, p, nil, m.Type(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match pacman package: %w", err)
	}
	return matches, ignoreFilters, nil
}
