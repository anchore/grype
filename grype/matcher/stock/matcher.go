package stock

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

var mainDistros = []distro.Type{
	distro.Ubuntu,
}

type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	UseCPEs bool
}

func NewStockMatcher(cfg MatcherConfig) match.Matcher {
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

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	//skip cpe matching for linux-kernel packages on major distros like ubuntu to avoid false positives from nvd's version ranges not covering backported fixes
	//kernel vulns are still found accurately using dpkg/rpm matchers with distro data that includes backported fixes
	if p.Type == syftPkg.LinuxKernelPkg && isMainDistro(p.Distro) {
		return nil, nil, nil
	}

	return internal.MatchPackageByEcosystemAndCPEs(store, p, m.Type(), m.cfg.UseCPEs)
}

func isMainDistro(d *distro.Distro) bool {
	if d == nil {
		return false
	}
	for _, comprehensive := range mainDistros {
		if d.Type == comprehensive {
			return true
		}
	}
	return false
}
