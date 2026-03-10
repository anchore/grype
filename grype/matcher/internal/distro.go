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

// FindDistroFixedIgnoreRules discovers vulnerabilities that the distro feed has data about but that do not
// affect the installed package version (i.e. the package is already at or beyond the fixed version). These
// "assessed-not-vulnerable" entries are returned as IgnoreRules so they can suppress false positive matches
// from language/ecosystem matchers (e.g. the GHSA/Python matcher) for the same CVE.
//
// This addresses the case where a distro backports a fix (e.g. RHEL patches python3-requests) but the
// upstream version number still looks vulnerable to the language-ecosystem advisory data. Without this,
// the language matcher would produce a false positive match.
//
// Importantly, when the distro feed has NO data about a CVE, no ignore rule is emitted, allowing the
// language matcher's verdict to stand -- this is the "search miss lets GHSA stand" behavior.
func FindDistroFixedIgnoreRules(provider vulnerability.Provider, searchPkg pkg.Package, cfg *version.ComparisonConfig) ([]match.IgnoreFilter, error) {
	if searchPkg.Distro == nil {
		return nil, nil
	}

	if isUnknownVersion(searchPkg.Version) {
		return nil, nil
	}

	// Phase 1: find ALL vulnerabilities the distro knows about for this package (without version filtering).
	allKnown, err := provider.FindVulnerabilities(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		OnlyQualifiedPackages(searchPkg),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch all known vulnerabilities distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	if len(allKnown) == 0 {
		// the distro has no data about this package at all -- nothing to suppress
		return nil, nil
	}

	// Phase 2: find only the vulnerabilities that actually affect the installed version.
	var pkgVersion *version.Version
	if cfg != nil {
		pkgVersion = version.NewWithConfig(searchPkg.Version, pkg.VersionFormat(searchPkg), *cfg)
	} else {
		pkgVersion = version.New(searchPkg.Version, pkg.VersionFormat(searchPkg))
	}

	vulnerable, err := provider.FindVulnerabilities(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		OnlyQualifiedPackages(searchPkg),
		OnlyVulnerableVersions(pkgVersion),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch vulnerable versions distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	// Phase 3: the difference is the "assessed-not-vulnerable" set -- the distro has data for these CVEs
	// but the installed version is already fixed.
	vulnerableIDs := make(map[string]struct{})
	for _, v := range vulnerable {
		vulnerableIDs[v.ID] = struct{}{}
	}

	var ignores []match.IgnoreFilter
	for _, v := range allKnown {
		if _, isVulnerable := vulnerableIDs[v.ID]; isVulnerable {
			continue
		}

		// collect all IDs (primary + related) so that alias resolution catches GHSA↔CVE mappings
		ids := collectVulnerabilityIDs(v)

		for _, id := range ids {
			ignores = append(ignores, match.IgnoreRule{
				Vulnerability:  id,
				IncludeAliases: true,
				Reason:         "DistroPackageFixed",
			})
		}
	}

	return ignores, nil
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
