package python

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
	return []pkg.Type{pkg.EggPkg, pkg.WheelPkg, pkg.PythonRequirementsPkg, pkg.PoetryPkg}
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
