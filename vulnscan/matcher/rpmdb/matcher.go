package rpmdb

import (
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/matcher/common"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
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
