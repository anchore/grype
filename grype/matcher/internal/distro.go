package internal

import (
	"fmt"
	"slices"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func MatchPackageByDistro(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) ([]match.Match, []match.IgnoreFilter, error) {
	if searchPkg.Distro == nil {
		return nil, nil, nil
	}

	if isUnknownVersion(searchPkg.Version) {
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	var matches []match.Match

	// Create version with config embedded if provided
	var pkgVersion *version.Version
	if cfg != nil {
		pkgVersion = version.NewWithConfig(searchPkg.Version, pkg.VersionFormat(searchPkg), *cfg)
	} else {
		pkgVersion = version.New(searchPkg.Version, pkg.VersionFormat(searchPkg))
	}

	versionCriteria := OnlyVulnerableVersions(pkgVersion)

	vulns, err := provider.FindVulnerabilities(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		OnlyQualifiedPackages(searchPkg),
		versionCriteria,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	for _, vuln := range vulns {
		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       matchPackage(searchPkg, catalogPkg),
			Details:       distroMatchDetails(upstreamMatcher, searchPkg, catalogPkg, vuln),
		})
	}
	return matches, nil, err
}

// MatchPackageByDistroWithOwnedFiles searches for all vulnerabilities the distro knows about for a
// package in a single query, then partitions the results in memory into vulnerable matches and
// location-scoped ignore rules for fixed vulnerabilities. The ignore rules are scoped to files
// owned by the package so they only suppress findings for co-located packages.
//
// Owned files are discovered by checking whether the package metadata (on either catalogPkg or
// searchPkg) implements [pkg.FileOwner]. When no owned files are available, this falls back to
// [MatchPackageByDistro] (version-filtered query, no ignore rules) to avoid over-fetching.
func MatchPackageByDistroWithOwnedFiles(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) ([]match.Match, []match.IgnoreFilter, error) {
	ownedFiles := ownedFilesFor(searchPkg, catalogPkg)
	if len(ownedFiles) == 0 {
		return MatchPackageByDistro(provider, searchPkg, catalogPkg, upstreamMatcher, cfg)
	}

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

	// Fetch all vulnerabilities the distro knows about for this package (1 query, no version filter).
	rp := result.NewProvider(provider, matchPackage(searchPkg, catalogPkg), upstreamMatcher)

	allVulns, err := rp.FindResults(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		OnlyQualifiedPackages(searchPkg),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	// Partition in memory: vulnerable vs. fixed.
	vulnerable, fixed := allVulns.Partition(versionCriteria)

	matches := vulnerable.ToMatches()
	ignores := distroFixedIgnoreRules(fixed, ownedFiles)

	return matches, ignores, nil
}

// distroFixedIgnoreRules builds location-scoped ignore rules for vulnerabilities that the distro has
// assessed as fixed. Each vulnerability ID (including aliases) gets one rule per owned path.
func distroFixedIgnoreRules(fixed result.Set, ownedFiles []string) []match.IgnoreFilter {
	var ignores []match.IgnoreFilter
	for _, results := range fixed {
		for _, r := range results {
			for _, v := range r.Vulnerabilities {
				ids := collectVulnerabilityIDs(v)
				for _, id := range ids {
					for _, path := range ownedFiles {
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

// ownedFilesFor returns the files owned by the package, preferring the catalog package's metadata
// (the SBOM package) over the search package's metadata (which may be a synthetic upstream).
func ownedFilesFor(searchPkg pkg.Package, catalogPkg *pkg.Package) []string {
	if catalogPkg != nil {
		if fo, ok := catalogPkg.Metadata.(pkg.FileOwner); ok {
			return fo.OwnedFiles()
		}
	}
	if fo, ok := searchPkg.Metadata.(pkg.FileOwner); ok {
		return fo.OwnedFiles()
	}
	return nil
}
