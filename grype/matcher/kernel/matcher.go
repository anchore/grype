package kernel

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

var distrosWithBackportedKernelFixes = []distro.Type{
	distro.Ubuntu,
}

type Matcher struct{}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.LinuxKernelPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.KernelMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	// Skip CPE matching for kernel packages on distros with backported fixes.
	// Kernel vulns are found via dpkg/rpm matchers with accurate distro data.
	if hasBackportedKernelFixes(p.Distro) {
		return nil, nil, nil
	}
	return nil, nil, nil
}

func hasBackportedKernelFixes(d *distro.Distro) bool {
	if d == nil {
		return false
	}
	for _, dt := range distrosWithBackportedKernelFixes {
		if d.Type == dt {
			return true
		}
	}
	return false
}
