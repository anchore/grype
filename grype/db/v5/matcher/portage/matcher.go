package portage

import (
	"fmt"

	"github.com/anchore/grype/grype/db/v5/search"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.PortagePkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.PortageMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoredMatch, error) {
	matches, err := search.ByPackageDistro(store, p, m.Type())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find vulnerabilities: %w", err)
	}

	return matches, nil, nil
}
