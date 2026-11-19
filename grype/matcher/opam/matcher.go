package opam

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// Matcher matches opam (OCaml) packages by ecosystem, e.g. against the OCaml
// security advisories, and optionally by CPE.
type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	UseCPEs bool
}

func NewOpamMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg: cfg,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.OpamPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.OpamMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	return internal.MatchPackageByEcosystemAndCPEs(store, p, m.Type(), m.cfg.UseCPEs)
}
