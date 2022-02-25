package search

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

var (
	ByCPE          Criteria = "by-cpe"
	ByLanguage     Criteria = "by-language"
	ByDistro       Criteria = "by-distro"
	CommonCriteria          = []Criteria{
		ByLanguage,
		ByCPE,
	}
)

type Criteria string

func ByCriteria(store vulnerability.Provider, d *distro.Distro, p pkg.Package, upstreamMatcher match.MatcherType, criteria ...Criteria) ([]match.Match, error) {
	matches := make([]match.Match, 0)
	for _, c := range criteria {
		switch c {
		case ByCPE:
			m, err := ByPackageCPE(store, p, upstreamMatcher)
			if err != nil {
				log.Debugf("could not match by package CPE: %v", err)
				continue
			}
			matches = append(matches, m...)
		case ByLanguage:
			m, err := ByPackageLanguage(store, p, upstreamMatcher)
			if err != nil {
				log.Debugf("could not match by package language: %v", err)
				continue
			}
			matches = append(matches, m...)
		case ByDistro:
			m, err := ByPackageDistro(store, d, p, upstreamMatcher)
			if err != nil {
				log.Debugf("could not match by package distro: %v", err)
				continue
			}
			matches = append(matches, m...)
		}
	}
	return matches, nil
}
