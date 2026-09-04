package rust

import (
	"errors"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	UseCPEs bool
}

func NewRustMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg: cfg,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.RustPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.RustMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	if isLocalCargoLockPackage(p) {
		if !m.cfg.UseCPEs {
			return nil, nil, nil
		}

		matches, ignored, err := internal.MatchPackageByCPEs(store, p, m.Type())
		switch {
		case errors.Is(err, internal.ErrEmptyCPEMatch):
			log.Debugf("attempted CPE search on %s, which has no CPEs. Consider re-running with --add-cpes-if-none", p.Name)
		case err != nil:
			log.Debugf("could not match by package CPE (package=%+v): %v", p, err)
		}

		return matches, ignored, nil
	}

	return internal.MatchPackageByEcosystemAndCPEs(store, p, m.Type(), m.cfg.UseCPEs)
}

func isLocalCargoLockPackage(p pkg.Package) bool {
	metadata, ok := p.Metadata.(pkg.RustMetadata)
	return ok && metadata.RustCargoLockSource == ""
}
