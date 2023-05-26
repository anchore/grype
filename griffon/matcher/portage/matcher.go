package portage

import (
	"fmt"

	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/nextlinux/griffon/griffon/distro"
	"github.com/nextlinux/griffon/griffon/match"
	"github.com/nextlinux/griffon/griffon/pkg"
	"github.com/nextlinux/griffon/griffon/search"
	"github.com/nextlinux/griffon/griffon/vulnerability"
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
	matches, err := search.ByPackageDistro(store, d, p, m.Type())
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities: %w", err)
	}

	return matches, nil
}
