package dpkg

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	MissingEpochStrategy string
}

func NewDpkgMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg: cfg,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.DebPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.DpkgMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	matches := make([]match.Match, 0)

	sourceMatches, err := m.matchUpstreamPackages(store, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by source indirection: %w", err)
	}
	matches = append(matches, sourceMatches...)

	versionConfig := version.ComparisonConfig{
		MissingEpochStrategy: m.cfg.MissingEpochStrategy,
	}
	exactMatches, _, err := internal.MatchPackageByDistro(store, p, nil, m.Type(), &versionConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by exact package name: %w", err)
	}
	matches = append(matches, exactMatches...)

	return matches, nil, nil
}

func (m *Matcher) matchUpstreamPackages(store vulnerability.Provider, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	versionConfig := version.ComparisonConfig{
		MissingEpochStrategy: m.cfg.MissingEpochStrategy,
	}
	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		indirectMatches, _, err := internal.MatchPackageByDistro(store, indirectPackage, &p, m.Type(), &versionConfig)
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
