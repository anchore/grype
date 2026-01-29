package kernel

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// mainDistros are distros where kernel vulnerabilities are handled by their
// native package matchers (dpkg/rpm) with distro-specific backport data.
// For these distros, the kernel matcher skips CPE matching to avoid false positives.
var mainDistros = []distro.Type{
	distro.Ubuntu,
}

type MatcherConfig struct {
	UseCPEs bool
}

type Matcher struct {
	cfg MatcherConfig
}

func NewKernelMatcher(cfg MatcherConfig) match.Matcher {
	return &Matcher{
		cfg: cfg,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.LinuxKernelPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.KernelMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	// Skip CPE matching for kernel packages on main distros.
	// Kernel vulns are found via dpkg/rpm matchers with accurate distro data.
	if isMainDistro(p.Distro) {
		return nil, nil, nil
	}
	// For non-main distros, use CPE-based matching
	return internal.MatchPackageByEcosystemAndCPEs(store, p, m.Type(), m.cfg.UseCPEs)
}

func isMainDistro(d *distro.Distro) bool {
	if d == nil {
		return false
	}
	for _, dt := range mainDistros {
		if d.Type == dt {
			return true
		}
	}
	return false
}
