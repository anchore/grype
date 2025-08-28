package internal

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func MatchPackageByLanguage(store vulnerability.Provider, p pkg.Package, matcherType match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match
	var ignored []match.IgnoreFilter

	for _, name := range store.PackageSearchNames(p) {
		nameMatches, nameIgnores, err := MatchPackageByEcosystemPackageName(store, p, name, matcherType)
		if err != nil {
			return nil, nil, err
		}
		matches = append(matches, nameMatches...)
		ignored = append(ignored, nameIgnores...)
	}

	return matches, ignored, nil
}

func MatchPackageByEcosystemPackageName(vp vulnerability.Provider, p pkg.Package, packageName string, matcherType match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	provider := result.NewProvider(vp, p, matcherType)

	criteria := []vulnerability.Criteria{
		search.ByEcosystem(p.Language, p.Type),
		search.ByPackageName(packageName),
		OnlyQualifiedPackages(p),
		OnlyVulnerableVersions(version.New(p.Version, pkg.VersionFormat(p))),
		OnlyNonWithdrawnVulnerabilities(),
	}

	// TODO: previous impl set confidence to 1, this results in
	// a confidence of zero. What should it be?
	disclosures, err := provider.FindResults(criteria...)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch disclosure language=%q pkg=%q: %w", p.Language, p.Name, err)
	}

	// we want to perform the same results, but look for explicit naks, which indicates that a vulnerability should not apply
	criteria = append(criteria, search.ForUnaffected(true))
	resolutions, err := provider.FindResults(criteria...)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch resolution language=%q pkg=%q: %w", p.Language, p.Name, err)
	}

	// remove any disclosures that have been explicitly nacked
	resolutions = addAliasesToResolutions(disclosures, resolutions)
	remaining := disclosures.Remove(resolutions)

	return remaining.ToMatches(), nil, err
}

// addAliasesToResolutions checks disclosures for aliases in resolutions, and adds disclosure id to the resolutions set
func addAliasesToResolutions(disclosures, resolutions result.Set) result.Set {
	for _, results := range disclosures {
		for _, result := range results {
			for _, vuln := range result.Vulnerabilities {
				for _, alias := range vuln.RelatedVulnerabilities {
					// if the alias is in resolutions, add the original vuln ID to the resolutions set
					if resolutions.Contains(alias.ID) {
						// TODO: could this use result.ID instead of vuln.ID?
						// NOTE: this must have at least one result, else contains would be false
						resolutions[vuln.ID] = results
					}
				}
			}
		}
	}
	return resolutions
}
