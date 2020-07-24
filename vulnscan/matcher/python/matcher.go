package python

import (
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/matcher/common"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []pkg.Type {
	return []pkg.Type{pkg.EggPkg, pkg.WheelPkg, pkg.PythonRequirementsPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.PythonMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, _ distro.Distro, p *pkg.Package) ([]match.Match, error) {
	var matches = make([]match.Match, 0)
	langMatches, err := common.FindMatchesByPackageLanguage(store, p.Language, p, m.Type())
	if err != nil {
		return nil, err
	}
	matches = append(matches, langMatches...)

	cpeMatches, err := common.FindMatchesByPackageCPE(store, p, m.Type())
	if err != nil {
		return nil, err
	}
	matches = append(matches, cpeMatches...)
	return matches, nil
}
