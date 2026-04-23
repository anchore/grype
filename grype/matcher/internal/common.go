package internal

import (
	"errors"
	"slices"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier/rootio"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func MatchPackageByEcosystemAndCPEs(store vulnerability.Provider, p pkg.Package, matcher match.MatcherType, includeCPEs bool) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match
	var ignored []match.IgnoreFilter

	searchNames := store.PackageSearchNames(p)

	// For rootio language packages, also search by the bare upstream name so that
	// CVE records stored without the rootio prefix (e.g. "Jinja2", "requests") are found.
	// The NAK subtraction handles suppression of vulns that rootio has already fixed.
	if rootio.IsRootIOPackage(p) {
		strippedName := rootio.StripPrefix(p.Name, p.Type)
		if strippedName != p.Name && !slices.Contains(searchNames, strippedName) {
			searchNames = append(searchNames, strippedName)
		}
	}

	for _, name := range searchNames {
		nameMatches, nameIgnores, err := MatchPackageByEcosystemPackageNameAndCPEs(store, p, name, matcher, includeCPEs)
		if err != nil {
			return nil, nil, err
		}
		matches = append(matches, nameMatches...)
		ignored = append(ignored, nameIgnores...)
	}

	return matches, ignored, nil
}

func MatchPackageByEcosystemPackageNameAndCPEs(store vulnerability.Provider, p pkg.Package, packageName string, matcher match.MatcherType, includeCPEs bool) ([]match.Match, []match.IgnoreFilter, error) {
	matches, ignored, err := MatchPackageByEcosystemPackageName(store, p, packageName, matcher)
	if err != nil {
		log.Debugf("could not match by package ecosystem (package=%+v): %v", p, err)
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
