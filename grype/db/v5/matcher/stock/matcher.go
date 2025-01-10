package stock

import (
	"github.com/anchore/grype/grype/db/v5/search"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	UseCPEs bool
}

func NewMatchProvider(cfg MatcherConfig) match.Matcher {
	return &Matcher{
		cfg: cfg,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return nil
}

func (m *Matcher) Type() match.MatcherType {
	return match.StockMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoredMatch, error) {
	out, err := search.ByPackageLanguage(store, p, m.Type())
	if err != nil {
		return nil, nil, err
	}
	if m.cfg.UseCPEs {
		cpeMatches, err := search.ByPackageCPE(store, p, m.Type())
		if err != nil {
			return nil, nil, err
		}
		out = append(out, cpeMatches...)
	}
	return out, nil, nil
}
