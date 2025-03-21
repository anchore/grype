package java

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

const (
	sha1Query = `1:"%s"`
)

type Matcher struct {
	MavenSearcher
	cfg MatcherConfig
}

type ExternalSearchConfig struct {
	SearchMavenUpstream bool
	MavenBaseURL        string
	MavenRateLimit      time.Duration
}

type MatcherConfig struct {
	ExternalSearchConfig
	UseCPEs bool
}

func NewJavaMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg:           cfg,
		MavenSearcher: newMavenSearch(http.DefaultClient, cfg.MavenBaseURL, cfg.MavenRateLimit),
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.JavaPkg, syftPkg.JenkinsPluginPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.JavaMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoredMatch, error) {
	var matches []match.Match

	if m.cfg.SearchMavenUpstream {
		upstreamMatches, err := m.matchUpstreamMavenPackages(store, p)
		if err != nil {
			if strings.Contains(err.Error(), "no artifact found") {
				log.Debugf("no upstream maven artifact found for %s", p.Name)
			} else {
				return nil, nil, match.NewFatalError(match.JavaMatcher, fmt.Errorf("resolving details for package %q with maven: %w", p.Name, err))
			}
		} else {
			matches = append(matches, upstreamMatches...)
		}
	}

	criteriaMatches, ignores, err := internal.MatchPackageByEcosystemAndCPEs(store, p, m.Type(), m.cfg.UseCPEs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by exact package: %w", err)
	}

	matches = append(matches, criteriaMatches...)

	return matches, ignores, nil
}

func (m *Matcher) matchUpstreamMavenPackages(store vulnerability.Provider, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	ctx := context.Background()

	// Check if we need to search Maven by SHA
	searchMaven, digests, err := m.shouldSearchMavenBySha(p)
	if err != nil {
		return nil, err
	}
	if searchMaven {
		// If the artifact and group ID exist are missing, attempt Maven lookup using SHA-1
		for _, digest := range digests {
			log.Debugf("searching maven, POM data missing for %s", p.Name)
			indirectPackage, err := m.GetMavenPackageBySha(ctx, digest)
			if err != nil {
				return nil, err
			}
			indirectMatches, _, err := internal.MatchPackageByLanguage(store, *indirectPackage, m.Type())
			if err != nil {
				return nil, err
			}
			matches = append(matches, indirectMatches...)
		}
	} else {
		log.Debugf("skipping maven search, POM data present for %s", p.Name)
		indirectMatches, _, err := internal.MatchPackageByLanguage(store, p, m.Type())
		if err != nil {
			return nil, err
		}
		matches = append(matches, indirectMatches...)
	}

	match.ConvertToIndirectMatches(matches, p)

	return matches, nil
}

func (m *Matcher) shouldSearchMavenBySha(p pkg.Package) (bool, []string, error) {
	digests := []string{}

	if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok {
		// if either the PomArtifactID or PomGroupID is missing, we need to search Maven
		if metadata.PomArtifactID == "" || metadata.PomGroupID == "" {
			for _, digest := range metadata.ArchiveDigests {
				if digest.Algorithm == "sha1" && digest.Value != "" {
					digests = append(digests, digest.Value)
				}
			}
			// If we need to search Maven but no valid SHA-1 digests exist, return an error
			if len(digests) == 0 {
				return true, nil, fmt.Errorf("missing SHA-1 digest; cannot search Maven for package %s", p.Name)
			}
		}
	}

	return len(digests) > 0, digests, nil
}
