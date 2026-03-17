package internal

import (
	"fmt"
	"slices"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// MatchPackageByDistro searches for vulnerabilities by distro package and returns matches for vulnerable
// entries. When ownedPaths is non-empty it also returns ignore rules for vulnerabilities the distro has
// assessed as fixed, scoped to those paths. This avoids suppressing findings for independently installed
// packages (e.g. a pip-installed package in a container that also has the distro package).
//
// When ownedPaths is empty the query includes version filtering for efficiency (only vulnerable entries
// are fetched). When ownedPaths is provided the superset of all known vulnerabilities is fetched in a
// single query and partitioned in memory, reducing the total number of database queries from 3 to 1.
func MatchPackageByDistro(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig, ownedPaths ...string) ([]match.Match, []match.IgnoreFilter, error) {
	if searchPkg.Distro == nil {
		return nil, nil, nil
	}

	if isUnknownVersion(searchPkg.Version) {
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	// Create version with config embedded if provided
	var pkgVersion *version.Version
	if cfg != nil {
		pkgVersion = version.NewWithConfig(searchPkg.Version, pkg.VersionFormat(searchPkg), *cfg)
	} else {
		pkgVersion = version.New(searchPkg.Version, pkg.VersionFormat(searchPkg))
	}

	versionCriteria := OnlyVulnerableVersions(pkgVersion)

	if len(ownedPaths) == 0 {
		// No ignore rules needed — add version criteria for an efficient, narrow query.
		return matchDistroVulnerable(provider, searchPkg, catalogPkg, upstreamMatcher, versionCriteria)
	}

	// Fetch the superset of all vulnerabilities the distro knows about for this package (1 query).
	allVulns, err := provider.FindVulnerabilities(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		OnlyQualifiedPackages(searchPkg),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	// Partition in memory: vulnerable vs. fixed.
	var matches []match.Match
	var fixedVulns []vulnerability.Vulnerability

	for _, vuln := range allVulns {
		isVulnerable, _, matchErr := versionCriteria.MatchesVulnerability(vuln)
		if matchErr != nil {
			return nil, nil, fmt.Errorf("failed to evaluate version criteria for %s: %w", vuln.ID, matchErr)
		}

		if isVulnerable {
			matches = append(matches, match.Match{
				Vulnerability: vuln,
				Package:       matchPackage(searchPkg, catalogPkg),
				Details:       distroMatchDetails(upstreamMatcher, searchPkg, catalogPkg, vuln),
			})
		} else {
			fixedVulns = append(fixedVulns, vuln)
		}
	}

	ignores := distroFixedIgnoreRules(fixedVulns, ownedPaths)

	return matches, ignores, nil
}

// matchDistroVulnerable is the fast path when no ignore rules are needed: it issues a single DB query
// that includes version criteria so only vulnerable entries are returned.
func matchDistroVulnerable(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, versionCriteria vulnerability.Criteria) ([]match.Match, []match.IgnoreFilter, error) {
	vulns, err := provider.FindVulnerabilities(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		OnlyQualifiedPackages(searchPkg),
		versionCriteria,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	var matches []match.Match
	for _, vuln := range vulns {
		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       matchPackage(searchPkg, catalogPkg),
			Details:       distroMatchDetails(upstreamMatcher, searchPkg, catalogPkg, vuln),
		})
	}
	return matches, nil, nil
}

// distroFixedIgnoreRules builds location-scoped ignore rules for vulnerabilities that the distro has
// assessed as fixed. Each vulnerability ID (including aliases) gets one rule per owned path.
func distroFixedIgnoreRules(fixedVulns []vulnerability.Vulnerability, ownedPaths []string) []match.IgnoreFilter {
	var ignores []match.IgnoreFilter
	for _, v := range fixedVulns {
		ids := collectVulnerabilityIDs(v)
		for _, id := range ids {
			for _, path := range ownedPaths {
				ignores = append(ignores, match.IgnoreRule{
					Vulnerability:  id,
					IncludeAliases: true,
					Reason:         "DistroPackageFixed",
					Package: match.IgnoreRulePackage{
						Location: path,
					},
				})
			}
		}
	}
	return ignores
}

func matchPackage(searchPkg pkg.Package, catalogPkg *pkg.Package) pkg.Package {
	if catalogPkg != nil {
		return *catalogPkg
	}
	return searchPkg
}

func distroMatchDetails(upstreamMatcher match.MatcherType, searchPkg pkg.Package, catalogPkg *pkg.Package, vuln vulnerability.Vulnerability) []match.Detail {
	ty := match.ExactIndirectMatch
	if catalogPkg == nil {
		ty = match.ExactDirectMatch
	}

	return []match.Detail{
		{
			Type:    ty,
			Matcher: upstreamMatcher,
			SearchedBy: match.DistroParameters{
				Distro: match.DistroIdentification{
					Type:    searchPkg.Distro.Type.String(),
					Version: searchPkg.Distro.Version,
				},
				Package: match.PackageParameter{
					Name:    searchPkg.Name,
					Version: searchPkg.Version,
				},
				Namespace: vuln.Namespace,
			},
			Found: match.DistroResult{
				VulnerabilityID:   vuln.ID,
				VersionConstraint: vuln.Constraint.String(),
			},
			Confidence: 1.0, // TODO: this is hard coded for now
		},
	}
}

// collectVulnerabilityIDs returns the primary ID plus all related/alias IDs for a vulnerability.
func collectVulnerabilityIDs(v vulnerability.Vulnerability) []string {
	ids := []string{v.ID}
	for _, related := range v.RelatedVulnerabilities {
		if !slices.Contains(ids, related.ID) {
			ids = append(ids, related.ID)
		}
	}
	return ids
}

func isUnknownVersion(v string) bool {
	return strings.ToLower(v) == "unknown"
}
