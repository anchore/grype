package rpmdb

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/common"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []pkg.Type {
	return []pkg.Type{pkg.RpmPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.RpmDBMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d distro.Distro, p *pkg.Package) ([]match.Match, error) {
	return common.FindMatchesByPackageDistro(store, d, p, m.Type())
}
