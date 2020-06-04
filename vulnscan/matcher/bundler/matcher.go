package bundler

import (
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/matcher/common"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

type Matcher struct {
}

func (m *Matcher) Types() []pkg.Type {
	return []pkg.Type{pkg.BundlerPkg}
}

func (m *Matcher) Name() string {
	return "bundler-matcher"
}

func (m *Matcher) Match(store vulnerability.Provider, d distro.Distro, p *pkg.Package) ([]match.Match, error) {
	return common.FindMatchesByPackageLanguage(store, p.Language, p, m.Name())
}
