package internal

import (
	"fmt"
	"slices"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier/rootio"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func MatchPackageByLanguage(store vulnerability.Provider, p pkg.Package, matcherType match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match
	var ignored []match.IgnoreFilter

	searchNames := store.PackageSearchNames(p)

	// For rootio language packages, also search by the bare upstream name so that
	// CVE records stored without the rootio prefix (e.g. "semver", "requests") are found.
	// The NAK subtraction in MatchPackageByEcosystemPackageName handles suppression of
	// vulns that rootio has already fixed.
	if rootio.IsRootIOPackage(p) {
		strippedName := rootio.StripPrefix(p.Name, p.Type)
		if strippedName != p.Name && !slices.Contains(searchNames, strippedName) {
			searchNames = append(searchNames, strippedName)
		}
	}

	for _, name := range searchNames {
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
	criteria = append(criteria, search.ForUnaffected())
	unaffected, err := provider.FindResults(criteria...)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch resolution language=%q pkg=%q: %w", p.Language, p.Name, err)
	}

	// remove any disclosures that have been explicitly nacked
	remaining := disclosures.Remove(unaffected)

	return remaining.ToMatches(), ConstructIgnoreFilters(unaffected, p), err
}

func ConstructIgnoreFilters(unaffectedVulns result.Set, p pkg.Package) []match.IgnoreFilter {
	var ignores []match.IgnoreFilter

	// collect all IDs to exclude
	var ids []string
	for _, vulnResults := range unaffectedVulns {
		for _, vulnResult := range vulnResults {
			ids = append(ids, vulnResult.ID)
			for _, vuln := range vulnResult.Vulnerabilities {
				if !slices.Contains(ids, vuln.ID) {
					ids = append(ids, vuln.ID)
				}
				for _, id := range vuln.RelatedVulnerabilities {
					if !slices.Contains(ids, id.ID) {
						ids = append(ids, id.ID)
					}
				}
			}
		}
	}

	// ignore rules for all IDs
	for _, id := range ids {
		ignores = append(ignores, match.IgnoreRule{
			Vulnerability:  id,
			IncludeAliases: true,
			Reason:         "UnaffectedPackageEntry",
			Package: match.IgnoreRulePackage{
				Type:    string(p.Type),
				Name:    p.Name,
				Version: p.Version,
			},
		})
	}
	return ignores
}
