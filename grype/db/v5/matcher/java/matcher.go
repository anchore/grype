package java

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/search"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
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

func (m *Matcher) Match(store v5.VulnerabilityProvider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match
	if m.cfg.SearchMavenUpstream {
		upstreamMatches, err := m.matchUpstreamMavenPackages(store, d, p)
		if err != nil {
			if strings.Contains(err.Error(), "no artifact found") {
				log.Debugf("no upstream maven artifact found for %s", p.Name)
			} else {
				log.WithFields("package", p.Name, "error", err).Warn("failed to resolve package details with maven")
			}
		} else {
			matches = append(matches, upstreamMatches...)
		}
	}
	criteria := search.CommonCriteria
	if m.cfg.UseCPEs {
		criteria = append(criteria, search.ByCPE)
	}
	criteriaMatches, err := search.ByCriteria(store, d, p, m.Type(), criteria...)
	if err != nil {
		return nil, fmt.Errorf("failed to match by exact package: %w", err)
	}

	matches = append(matches, criteriaMatches...)
	return matches, nil
}

func (m *Matcher) matchUpstreamMavenPackages(store v5.VulnerabilityProvider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	ctx := context.Background()

	if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok {
		for _, digest := range metadata.ArchiveDigests {
			if digest.Algorithm == "sha1" {
				indirectPackage, err := m.GetMavenPackageBySha(ctx, digest.Value)
				if err != nil {
					return nil, err
				}
				indirectMatches, err := search.ByPackageLanguage(store, d, *indirectPackage, m.Type())
				if err != nil {
					return nil, err
				}
				matches = append(matches, indirectMatches...)
			}
		}
	}

	match.ConvertToIndirectMatches(matches, p)

	return matches, nil
}
