package jvm

import (
	"fmt"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type MatcherConfig struct {
	UseCPEs bool
}

type Matcher struct {
	cfg MatcherConfig
}

func NewJVMMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg: cfg,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.BinaryPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.JVMMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	if !pkg.IsJvmPackage(p) {
		return nil, nil
	}

	criteria := search.CommonCriteria
	if m.cfg.UseCPEs {
		criteria = append(criteria, search.ByCPE)
	}
	matches, err := search.ByCriteria(store, d, p, m.Type(), criteria...)
	if err != nil {
		return nil, fmt.Errorf("failed to match by exact package: %w", err)
	}

	return matches, nil
}
