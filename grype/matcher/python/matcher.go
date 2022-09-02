package python

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
	UseCPEs bool
}

type MatcherConfig struct {
	UseCPEs bool
}

func NewPythonMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		UseCPEs: cfg.UseCPEs,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.PythonPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.PythonMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	criteria := search.CommonCriteria
	if m.UseCPEs {
		criteria = append(criteria, search.ByCPE)
	}
	return search.ByCriteria(store, d, p, m.Type(), criteria...)
}
