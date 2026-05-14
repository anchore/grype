package internal

import (
	"errors"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// MatchPackageByEcosystemAndCPEs runs the ecosystem-by-name search (via
// MatchPackageByLanguage, which handles the multi-name fanout and cross-name
// NAK Remove internally) and, if enabled, the CPE search, then combines the
// results.
func MatchPackageByEcosystemAndCPEs(store vulnerability.Provider, p pkg.Package, matcher match.MatcherType, includeCPEs bool) ([]match.Match, []match.IgnoreFilter, error) {
	matches, ignored, err := MatchPackageByLanguage(store, p, matcher)
	if err != nil {
		log.Debugf("could not match by package ecosystem (package=%+v): %v", p, err)
	}

	if includeCPEs {
		cpeMatches, cpeIgnores, cpeErr := MatchPackageByCPEs(store, p, matcher)
		switch {
		case errors.Is(cpeErr, ErrEmptyCPEMatch):
			log.Debugf("attempted CPE search on %s, which has no CPEs. Consider re-running with --add-cpes-if-none", p.Name)
		case cpeErr != nil:
			log.Debugf("could not match by package CPE (package=%+v): %v", p, cpeErr)
		}
		matches = append(matches, cpeMatches...)
		ignored = append(ignored, cpeIgnores...)
	}

	return matches, ignored, nil
}
