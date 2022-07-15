package portage

import (
	"fmt"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
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

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	matches, err := search.ByCriteria(store, d, p, m.Type(), search.CommonCriteria...)
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities: %w", err)
	}

	return matches, nil
}
