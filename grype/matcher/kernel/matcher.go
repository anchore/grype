package kernel

import (
	"fmt"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// distrosWithReliableKernelData are distros where kernel vulnerabilities are handled by their
// native package matchers (dpkg/rpm) with distro-specific backport data.
// For these distros, the kernel matcher skips CPE matching to avoid false positives.
var distrosWithReliableKernelData = []distro.Type{
	distro.AmazonLinux,
	distro.Alpine,
	distro.Ubuntu,
	distro.Debian,
	distro.Fedora,
	distro.RedHat,
	distro.SLES,
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
	var matches []match.Match

	if hasReliableKernelData(p.Distro) {
		sourceMatches, err := m.matchUpstreamPackages(store, p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match by src indirection: %w", err)
		}
		matches = append(matches, sourceMatches...)

		exactMatches, _, err := internal.MatchPackageByDistro(store, p, nil, m.Type())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match by exact pkg name: %w", err)
		}
		matches = append(matches, exactMatches...)

		return matches, nil, nil
	}

	// fallback cpe
	if m.cfg.UseCPEs {
		return internal.MatchPackageByEcosystemAndCPEs(store, p, m.Type(), true)
	}

	return nil, nil, nil
}

func (m *Matcher) matchUpstreamPackages(store vulnerability.Provider, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		indirectMatches, _, err := internal.MatchPackageByDistro(store, indirectPackage, &p, m.Type())
		if err != nil {
			return nil, fmt.Errorf("failed to find vuln for kernel upstream src pkg: %w", err)
		}
		matches = append(matches, indirectMatches...)
	}

	match.ConvertToIndirectMatches(matches, p)

	return matches, nil
}

func hasReliableKernelData(d *distro.Distro) bool {
	if d == nil {
		return false
	}
	for _, reliable := range distrosWithReliableKernelData {
		if d.Type == reliable {
			return true
		}
	}
	return false
}
