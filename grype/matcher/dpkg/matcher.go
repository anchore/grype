package dpkg

import (
	"fmt"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.DebPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.DpkgMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	matches := make([]match.Match, 0)

	sourceMatches, err := m.matchUpstreamPackages(store, d, p)
	if err != nil {
		return nil, fmt.Errorf("failed to match by source indirection: %w", err)
	}
	matches = append(matches, sourceMatches...)

	exactMatches, err := search.ByPackageDistro(store, d, p, m.Type())
	if err != nil {
		return nil, fmt.Errorf("failed to match by exact package name: %w", err)
	}
	matches = append(matches, exactMatches...)

	return matches, nil
}

func (m *Matcher) matchUpstreamPackages(store vulnerability.ProviderByDistro, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	for indirectPackage := range pkg.UpstreamPackages(p) {
		indirectMatches, err := search.ByPackageDistro(store, d, indirectPackage, m.Type())
		if err != nil {
			return nil, fmt.Errorf("failed to find vulnerabilities for dpkg upstream source package: %w", err)
		}
		matches = append(matches, indirectMatches...)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the indirect package)
	// however, we also want to keep the indirect package around for future reference
	match.ConvertToIndirectMatches(matches, p)

	return matches, nil
}
