package internal

import (
	"errors"

	"github.com/anchore/grype/grype/db/v5/pkg/resolver"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

//
// var (
//	ByCPE          Criteria = "by-cpe"
//	ByLanguage     Criteria = "by-language"
//	ByDistro       Criteria = "by-distro"
//	CommonCriteria          = []Criteria{
//		ByLanguage,
//	}
//)
//
// type Criteria string
//
// func (m *Matcher) MatchByCriteria(store vulnerability.Provider, p pkg.Package, upstreamMatcher match.MatcherType, criteria ...Criteria) ([]match.Match, []match.IgnoredMatch, error) {
//	matches := make([]match.Match, 0)
//	for _, c := range criteria {
//		switch c {
//		case ByCPE:
//		case ByLanguage:
//			matches = append(matches, m...)
//		case ByDistro:
//			m, err := m.MatchPackageByDistro(store, p, upstreamMatcher)
//			if err != nil {
//				log.Warnf("could not match by package distro (package=%+v): %v", p, err)
//				continue
//			}
//			matches = append(matches, m...)
//		}
//	}
//	return matches, nil, nil
//}

func MatchPackageByLanguageAndCPEs(store vulnerability.Provider, p pkg.Package, matcher match.MatcherType, includeCPEs bool) ([]match.Match, []match.IgnoredMatch, error) {
	matches, ignored, err := MatchPackageByLanguage(store, p, getPackageNames, matcher)
	if err != nil {
		log.Debugf("could not match by package language (package=%+v): %v", p, err)
	}
	if includeCPEs {
		cpeMatches, err := MatchPackageByCPEs(store, p, matcher)
		if errors.Is(err, ErrEmptyCPEMatch) {
			log.Debugf("attempted CPE search on %s, which has no CPEs. Consider re-running with --add-cpes-if-none", p.Name)
		} else if err != nil {
			log.Debugf("could not match by package CPE (package=%+v): %v", p, err)
		}
		matches = append(matches, cpeMatches...)
	}
	return matches, ignored, nil
}

func getPackageNames(p pkg.Package) []string {
	r, _ := resolver.FromLanguage(p.Language)
	if r != nil {
		return r.Resolve(p)
	}
	return []string{p.Name}
}

func DirectName(p pkg.Package) []string {
	return []string{p.Name}
}
