package dpkg

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	MissingEpochStrategy version.MissingEpochStrategy
	UseCPEsForEOL        bool
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
	matches, ignores, err := m.matchUpstreamPackages(store, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by source indirection: %w", err)
	}

	versionConfig := version.ComparisonConfig{
		MissingEpochStrategy: m.cfg.MissingEpochStrategy,
	}
	exactMatches, exactIgnores, err := internal.MatchPackageByDistro(store, p, nil, m.Type(), &versionConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by exact package name: %w", err)
	}
	matches = append(matches, exactMatches...)
	ignores = append(ignores, exactIgnores...)

	// if configured, also search by CPEs for packages from EOL distros
	if m.cfg.UseCPEsForEOL && internal.IsDistroEOL(store, p.Distro) {
		log.WithFields("package", p.Name, "distro", p.Distro).Debug("distro is EOL, searching by CPEs")
		cpeMatches, ignored, err := internal.MatchPackageByCPEs(store, p, m.Type())
		switch {
		case errors.Is(err, internal.ErrEmptyCPEMatch):
			log.WithFields("package", p.Name).Debug("package has no CPEs for EOL fallback matching")
		case err != nil:
			log.WithFields("package", p.Name, "error", err).Debug("failed to match by CPEs for EOL distro")
		default:
			matches = append(matches, cpeMatches...)
			ignores = append(ignores, ignored...)
		}
	}

	return matches, ignores, nil
}

func (m *Matcher) matchUpstreamPackages(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match
	var ignores []match.IgnoreFilter

	versionConfig := version.ComparisonConfig{
		MissingEpochStrategy: m.cfg.MissingEpochStrategy,
	}
	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		indirectMatches, ignored, err := internal.MatchPackageByDistro(store, indirectPackage, &p, m.Type(), &versionConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to find vulnerabilities for dpkg upstream source package: %w", err)
		}
		matches = append(matches, indirectMatches...)
		ignores = append(ignores, ignored...)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the indirect package)
	// however, we also want to keep the indirect package around for future reference
	match.ConvertToIndirectMatches(matches, p)

	return matches, ignores, nil
}
