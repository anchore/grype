package golang

import (
	"strings"

	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/nextlinux/griffon/griffon/distro"
	"github.com/nextlinux/griffon/griffon/match"
	"github.com/nextlinux/griffon/griffon/pkg"
	"github.com/nextlinux/griffon/griffon/search"
	"github.com/nextlinux/griffon/griffon/vulnerability"
)

type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	UseCPEs bool
}

func NewGolangMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg: cfg,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.GoModulePkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.GoModuleMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	matches := make([]match.Match, 0)

	mainModule := ""
	if m, ok := p.Metadata.(pkg.GolangBinMetadata); ok {
		mainModule = m.MainModule
	}

	// Golang currently does not have a standard way of incorporating the vcs version
	// into the compiled binary: https://github.com/golang/go/issues/50603
	// current version information for the main module is incomplete leading to multiple FP
	// TODO: remove this exclusion when vcs information is included in future go version
	isNotCorrected := strings.HasPrefix(p.Version, "v0.0.0-") || strings.HasPrefix(p.Version, "(devel)")
	if p.Name == mainModule && isNotCorrected {
		return matches, nil
	}

	criteria := search.CommonCriteria
	if m.cfg.UseCPEs {
		criteria = append(criteria, search.ByCPE)
	}
	return search.ByCriteria(store, d, p, m.Type(), criteria...)
}
