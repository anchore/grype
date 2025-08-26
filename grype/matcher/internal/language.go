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

	disclosures, err := provider.FindResults(criteria...)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch disclosure language=%q pkg=%q: %w", p.Language, p.Name, err)
	}

	// we want to perform the same results, but look for explicit naks, which indicates that a vulnerability should not apply
	criteria = append(criteria, search.ForUnaffected())

	resolutions, err := provider.FindResults(criteria...)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch resolution language=%q pkg=%q: %w", p.Language, p.Name, err)
	}

	remaining := disclosures.Remove(resolutions)

	return remaining.ToMatches(), nil, err
}

//// getIgnoreFilter get ignore filters for this package and vuln
//func getIgnoreFilter(p *pkg.Package, vuln *vulnerability.Vulnerability) []match.IgnoreFilter {
//	// if this has fixes, add to ignore
//	ignores := make([]match.IgnoreFilter, 0, len(vuln.Fix.Versions))
//	for _, fix := range vuln.Fix.Versions {
//		// TODO: compare to grype/vex/openvex/implementation.go
//		ignores = append(ignores, match.IgnoreRule{
//			Vulnerability: vuln.ID,
//			Reason:        "Fix",
//			Namespace:     vuln.Namespace,
//			FixState:      vulnerability.FixStateFixed.String(),
//			Package: match.IgnoreRulePackage{
//				Name: p.Name,
//				// TODO the fix for 1.2.3+foo.1 should apply to any version 1.2.3+foo.N for n >= 1
//				Version:  fix,
//				Language: string(p.Language),
//				Type:     string(p.Type),
//				// Location: p.Locations[0].
//				// UpstreamName: p.Name,
//			},
//			VexStatus: vuln.Status,
//			MatchType: match.ExactDirectMatch,
//			// IncludeAliases: vuln.,
//			// VexJustification: vuln.
//		})
//	}
//	return ignores
//}
//
//// filterFixVersions get only the fixes related to this package.
////
//// Uses semver metadata to retrieve unspecified fixes or fixes with matching metadata
//// IE, X.Y.Z+foo.1 and X.Y.Z both match A.B.C+foo.2, but not X.Y.Z+bar.1
//func filterFixVersions(pkgVer string, fixVers []string) ([]string, error) {
//	pkgVersion, err := hashiVer.NewSemver(pkgVer)
//	if err != nil {
//		return nil, fmt.Errorf("pkg is not a valid semver %s: %w", pkgVer, err)
//	}
//	// filter fix versions by semver metadata
//	fixes := make([]string, 0, len(fixVers))
//	for _, fix := range fixVers {
//		fixVersion, err := hashiVer.NewSemver(fix)
//		if err != nil {
//			return nil, err
//		}
//		// compare version metadata pre period, assuming vendors will user `vendorid.subversion` syntax
//		fixMeta, _, _ := strings.Cut(fixVersion.Metadata(), ".")
//		pkgMeta, _, _ := strings.Cut(pkgVersion.Metadata(), ".")
//		// if the fix is unspecified or matches on meta, return
//		if fixMeta == "" || fixMeta == pkgMeta {
//			fixes = append(fixes, fix)
//		}
//	}
//	return fixes, nil
//}
