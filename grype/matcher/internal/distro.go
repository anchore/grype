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

// FindResultsByDistro searches the distro namespace for every name the
// provider claims for searchPkg, then partitions the unioned results in
// memory into vulnerable disclosures and fixed records (folding the distro
// "unaffected"/NAK records into fixed). It returns result.Sets so callers can
// reconcile them against other sources (e.g. NVD/CPE) by identity, or convert
// to matches + ignores via MatchPackageByDistro.
//
// The fanout over PackageSearchNames is what makes the rootio NAK pattern
// work: a scan against `rootio-libssl3` also searches for the bare
// `libssl3` upstream disclosure, and any rootio NAK in the unaffected set
// suppresses the match via ID + alias identity in result.Set.Remove.
func FindResultsByDistro(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) (vulnerable result.Set, fixed result.Set, err error) {
	if searchPkg.Distro == nil {
		return result.Set{}, result.Set{}, nil
	}

	if isUnknownVersion(searchPkg.Version) {
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
		return result.Set{}, result.Set{}, nil
	}

	var pkgVersion *version.Version
	if cfg != nil {
		pkgVersion = version.NewWithConfig(searchPkg.Version, pkg.VersionFormat(searchPkg), *cfg)
	} else {
		pkgVersion = version.New(searchPkg.Version, pkg.VersionFormat(searchPkg))
	}

	versionCriteria := OnlyVulnerableVersions(pkgVersion)
	rp := result.NewProvider(provider, matchPackage(searchPkg, catalogPkg), upstreamMatcher)

	// Search by every name the provider claims for this package. For most
	// packages that's just one name; rootio packages fan out to the bare
	// upstream name so we find disclosures stored without the rootio prefix.
	searchNames := provider.PackageSearchNames(searchPkg)

	allVulns := result.Set{}
	for _, name := range searchNames {
		v, err := rp.FindResults(
			search.ByPackageName(name),
			search.ByDistro(*searchPkg.Distro),
			OnlyQualifiedPackages(searchPkg),
			OnlyNonWithdrawnVulnerabilities(),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", searchPkg.Distro, name, err)
		}
		allVulns = allVulns.Merge(v)
	}

	vulnerable = allVulns.Filter(versionCriteria)
	fixed = allVulns.Remove(vulnerable)

	unaffected := result.Set{}
	for _, name := range searchNames {
		u, err := rp.FindResults(
			search.ByDistro(*searchPkg.Distro),
			search.ByPackageName(name),
			search.ForUnaffected(),
			versionCriteria,
			OnlyNonWithdrawnVulnerabilities(),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("matcher failed to fetch unaffected distro=%q pkg=%q: %w", searchPkg.Distro, name, err)
		}
		unaffected = unaffected.Merge(u)
	}

	vulnerable = vulnerable.Remove(unaffected)
	fixed = fixed.Merge(unaffected)

	return vulnerable, fixed, nil
}

// MatchPackageByDistro searches the distro namespace for every name the
// provider claims for searchPkg, then partitions the unioned results in
// memory into vulnerable matches and fixes the matcher should ignore on
// overlapping packages (e.g. an APK that owns NPM). It is a thin wrapper over
// FindResultsByDistro for callers that work in []match.Match.
func MatchPackageByDistro(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) ([]match.Match, []match.IgnoreFilter, error) {
	vulnerable, fixed, err := FindResultsByDistro(provider, searchPkg, catalogPkg, upstreamMatcher, cfg)
	if err != nil {
		return nil, nil, err
	}

	// Use the SBOM package (not the synthetic upstream) for file ownership — the upstream package doesn't have file metadata.
	ignores := OwnershipIgnores(matchPackage(searchPkg, catalogPkg), "DistroPackageFixed", fixed.Vulnerabilities()...)

	return vulnerable.ToMatches(), ignores, nil
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
