package internal

import (
	"errors"

	"github.com/anchore/grype/grype/db/v5/pkg/resolver"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func PackageNames(p pkg.Package) []string {
	names := []string{p.Name}
	r, _ := resolver.FromLanguage(p.Language)
	if r != nil {
		parts := r.Resolve(p)
		if len(parts) > 0 {
			names = parts
		}
	}
	return names
}

func MatchPackageByLanguageAndCPEs(store vulnerability.Provider, p pkg.Package, matcher match.MatcherType, includeCPEs bool) ([]match.Match, []match.IgnoredMatch, error) {
	var matches []match.Match
	var ignored []match.IgnoredMatch

	for _, name := range PackageNames(p) {
		nameMatches, nameIgnores, err := MatchPackageByLanguagePackageNameAndCPEs(store, p, name, matcher, includeCPEs)
		if err != nil {
			return nil, nil, err
		}
		matches = append(matches, nameMatches...)
		ignored = append(ignored, nameIgnores...)
	}

	return matches, ignored, nil
}

func MatchPackageByLanguagePackageNameAndCPEs(store vulnerability.Provider, p pkg.Package, packageName string, matcher match.MatcherType, includeCPEs bool) ([]match.Match, []match.IgnoredMatch, error) {
	matches, ignored, err := MatchPackageByLanguagePackageName(store, p, packageName, matcher)
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
