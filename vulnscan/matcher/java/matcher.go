package java

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
	return []pkg.Type{pkg.JavaPkg, pkg.JenkinsPluginPkg}
}

func (m *Matcher) Name() string {
	return "java-matcher"
}

func (m *Matcher) Match(store vulnerability.Provider, _ distro.Distro, p *pkg.Package) ([]match.Match, error) {
	var matches = make([]match.Match, 0)
	langMatches, err := common.FindMatchesByPackageLanguage(store, p.Language, p, m.Name())
	if err != nil {
		return nil, err
	}
	matches = append(matches, langMatches...)

	cpeMatches, err := common.FindMatchesByPackageCPE(store, p, m.Name())
	if err != nil {
		return nil, err
	}
	matches = append(matches, cpeMatches...)
	return matches, nil
}
