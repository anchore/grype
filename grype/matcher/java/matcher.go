package java

import (
	"fmt"
	"net/http"

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
}

type MatcherConfig struct {
	ExternalSearchConfig
	UseCPEs bool
}

func NewJavaMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg: cfg,
		MavenSearcher: &mavenSearch{
			client:  http.DefaultClient,
			baseURL: cfg.MavenBaseURL,
		},
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
			log.Debugf("failed to match against upstream data for %s: %v", p.Name, err)
		} else {
			matches = append(matches, upstreamMatches...)
		}
	}

	criteriaMatches, ignores, err := internal.MatchPackageByLanguageAndCPEs(store, p, m.Type(), m.cfg.UseCPEs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by exact package: %w", err)
	}

	matches = append(matches, criteriaMatches...)

	return matches, ignores, nil
}

func (m *Matcher) matchUpstreamMavenPackages(store vulnerability.Provider, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok {
		for _, digest := range metadata.ArchiveDigests {
			if digest.Algorithm == "sha1" {
				indirectPackage, err := m.GetMavenPackageBySha(digest.Value)
				if err != nil {
					return nil, err
				}
				indirectMatches, _, err := internal.MatchPackageByLanguage(store, *indirectPackage, m.Type())
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
