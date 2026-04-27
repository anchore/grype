package internal

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// MatchPackageByDistro searches for all vulnerabilities the distro knows about for a
// package in a single query, then partitions the results in memory into vulnerable matches and
// fixes to ignore on overlapping packages such as an APK which owns NPM
func MatchPackageByDistro(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) ([]match.Match, []match.IgnoreFilter, error) {
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

	// Split in memory: vulnerable vs. fixed.
	vulnerable := allVulns.Filter(versionCriteria)
	fixed := allVulns.Remove(vulnerable)

	// include any unaffected results that match this package as filters
	unaffected, err := rp.FindResults(
		search.ByDistro(*searchPkg.Distro),
		search.ByPackageName(searchPkg.Name),
		search.ForUnaffected(),
		versionCriteria,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch unaffected distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	// remove any unaffected results that match this package as matches
	vulnerable = vulnerable.Remove(unaffected)

	fixed = fixed.Merge(unaffected)

	// Use the SBOM package (not the synthetic upstream) for file ownership — the upstream package doesn't have file metadata.
	ignores := OwnershipIgnores(matchPackage(searchPkg, catalogPkg), "DistroPackageFixed", fixed.Vulnerabilities()...)

	matches := vulnerable.ToMatches()

	return matches, ignores, nil
}

func matchPackage(searchPkg pkg.Package, catalogPkg *pkg.Package) pkg.Package {
	if catalogPkg != nil {
		return *catalogPkg
	}
	return searchPkg
}

func isUnknownVersion(v string) bool {
	return strings.ToLower(v) == "unknown"
}
