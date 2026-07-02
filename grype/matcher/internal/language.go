package internal

import (
	"fmt"
	"slices"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier/echo"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// unaffectedVersionCriteria returns the version criteria used to evaluate
// unaffected (NAK) records. Echo-patched builds of SemVer-versioned packages
// (e.g. npm) need the echo-aware format: SemVer excludes the "+echo.N" build
// number from precedence, so under the default format a NAK fixed at
// "+echo.2" would also suppress the still-vulnerable "+echo.1" build.
// Disclosures intentionally keep the default format — upstream advisories are
// written against upstream versions and must keep treating "X+echo.N" as "X"
// (e.g. an unfixed "<= X" advisory must still apply to X+echo.N).
func unaffectedVersionCriteria(p pkg.Package, defaultCriteria vulnerability.Criteria) vulnerability.Criteria {
	format := pkg.VersionFormat(p)
	if (format == version.UnknownFormat || format == version.SemanticFormat) && echo.IsEchoBuild(p.Version) {
		return OnlyVulnerableVersions(version.New(p.Version, version.EchoFormat))
	}
	return defaultCriteria
}

func MatchPackageByLanguage(store vulnerability.Provider, p pkg.Package, matcherType match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	provider := result.NewProvider(store, p, matcherType)
	versionCriteria := OnlyVulnerableVersions(version.New(p.Version, pkg.VersionFormat(p)))
	nakVersionCriteria := unaffectedVersionCriteria(p, versionCriteria)

	disclosures := result.Set{}
	unaffected := result.Set{}

	// Gather disclosures and unaffected entries across every name the
	// provider claims for p, then run the cross-name Remove. Doing the
	// Remove per-name would silo a NAK keyed under one name (e.g.
	// `rootio-foo`) away from a disclosure keyed under another (`foo`).
	for _, name := range store.PackageSearchNames(p) {
		criteria := []vulnerability.Criteria{
			search.ByEcosystem(p.Language, p.Type),
			search.ByPackageName(name),
			OnlyQualifiedPackages(p),
			OnlyNonWithdrawnVulnerabilities(),
		}

		all, err := provider.FindResults(criteria...)
		if err != nil {
			return nil, nil, fmt.Errorf("matcher failed to fetch disclosure language=%q pkg=%q: %w", p.Language, name, err)
		}
		disclosures = disclosures.Merge(all.Filter(versionCriteria))

		nakCriteria := append(slices.Clone(criteria), search.ForUnaffected(), nakVersionCriteria)
		u, err := provider.FindResults(nakCriteria...)
		if err != nil {
			return nil, nil, fmt.Errorf("matcher failed to fetch resolution language=%q pkg=%q: %w", p.Language, name, err)
		}
		unaffected = unaffected.Merge(u)
	}

	remaining := disclosures.Remove(unaffected)
	return remaining.ToMatches(), constructIgnoreFilters(unaffected, p), nil
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
		OnlyNonWithdrawnVulnerabilities(),
	}

	versionCriteria := OnlyVulnerableVersions(version.New(p.Version, pkg.VersionFormat(p)))

	// TODO: previous impl set confidence to 1, this results in
	// a confidence of zero. What should it be?
	all, err := provider.FindResults(criteria...)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch disclosure language=%q pkg=%q: %w", p.Language, p.Name, err)
	}

	disclosures := all.Filter(versionCriteria)

	// we want to perform the same results, but look for explicit naks, which indicates that a vulnerability should not apply
	criteria = append(criteria, search.ForUnaffected(), unaffectedVersionCriteria(p, versionCriteria))
	unaffected, err := provider.FindResults(criteria...)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch resolution language=%q pkg=%q: %w", p.Language, p.Name, err)
	}

	// remove any disclosures that have been explicitly nacked
	remaining := disclosures.Remove(unaffected)

	return remaining.ToMatches(), constructIgnoreFilters(unaffected, p), err
}

func constructIgnoreFilters(unaffectedVulns result.Set, p pkg.Package) []match.IgnoreFilter {
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
