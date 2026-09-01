package dpkg

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/matcher/internal/result"
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
	var matches []match.Match
	var ignores []match.IgnoreFilter

	// Ubuntu ESM (Pro) distros need a two-pass disclosure/resolution match to resolve base disclosures against
	// ESM-channel fixes, covering both the binary and its source packages. Non-ESM dpkg scans keep the standard path.
	if shouldUseUbuntuESMMatching(p.Distro) {
		esmMatches, esmIgnores, err := m.matchUbuntuESM(store, p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match Ubuntu ESM: %w", err)
		}
		matches = append(matches, esmMatches...)
		ignores = append(ignores, esmIgnores...)
	} else {
		versionConfig := version.ComparisonConfig{
			MissingEpochStrategy: m.cfg.MissingEpochStrategy,
		}
		// the binary and its source packages are split together: ubuntu and debian data is
		// source-keyed, so the fix that answers a binary's disclosure is routinely stored under the
		// source name, and only one split over both can let it do so
		exactMatches, exactIgnores, err := internal.MatchPackageByDistroAcrossUpstreams(store, p, m.Type(), &versionConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match by exact package name: %w", err)
		}
		matches = append(matches, exactMatches...)
		ignores = append(ignores, exactIgnores...)
	}

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

// matchUbuntuESM matches an Ubuntu Pro/ESM package using the two-pass disclosure/resolution search, covering both
// the binary package and each of its source (upstream) packages. Ubuntu vulnerability data is source-keyed, so the
// upstream pass is what actually resolves most fixes. The shared result provider is built from the binary package p,
// so upstream matches are automatically recorded as indirect (and keyed to p) by the result detail logic.
func (m *Matcher) matchUbuntuESM(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	provider := result.NewProvider(store, p, m.Type())

	matches, ignores, err := ubuntuESMMatches(provider, p, m.cfg.MissingEpochStrategy)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by exact package name: %w", err)
	}

	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		indirectMatches, indirectIgnores, err := ubuntuESMMatches(provider, indirectPackage, m.cfg.MissingEpochStrategy)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to find vulnerabilities for dpkg upstream source package: %w", err)
		}
		matches = append(matches, indirectMatches...)
		ignores = append(ignores, indirectIgnores...)
	}

	return matches, ignores, nil
}
