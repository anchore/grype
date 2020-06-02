package dpkg

import (
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	_distro "github.com/anchore/vulnscan/vulnscan/matcher/distro"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

type Matcher struct {
	_distro.Matcher
}

func (m *Matcher) Types() []pkg.Type {
	return []pkg.Type{pkg.DebPkg}
}

func (m *Matcher) Match(store vulnerability.Provider, d distro.Distro, p *pkg.Package) ([]match.Match, error) {
	// TODO: add match by dpkg.metadata.source ...

	return m.ExactPackageNameMatch(store, d, p)
}
