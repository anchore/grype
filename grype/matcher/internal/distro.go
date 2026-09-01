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

// FindResultsByDistro searches the distro feed for every name the provider claims for searchPkg,
// then splits the unioned records into the ones this version is vulnerable to and everything else.
// It returns result.Sets so callers can reconcile them against other sources (e.g. NVD/CPE) by
// identity, or convert to matches + ignores via MatchPackageByDistro.
//
// notVulnerable is broader than "fixed": alongside records already fixed at this version it holds
// the ones whose ranges do not cover this build at all, the ones a more specific release stream
// overruled, and the feed's explicit "unaffected"/NAK records. That is what makes it the right
// thing to reconcile other sources against, and the right thing to build ownership ignores from.
//
// The fanout over PackageSearchNames is what makes the rootio NAK pattern work: a scan against
// `rootio-libssl3` also searches for the bare `libssl3` upstream disclosure, and any rootio NAK
// turned up alongside it denies the match by ID + alias identity.
func FindResultsByDistro(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) (vulnerable result.Set, notVulnerable result.Set, err error) {
	if searchPkg.Distro == nil {
		return result.Set{}, result.Set{}, nil
	}

	if isUnknownVersion(searchPkg.Version) {
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
		return result.Set{}, result.Set{}, nil
	}

	pkgVersion := distroVersion(searchPkg, cfg)

	rp := result.NewProvider(provider, matchPackage(searchPkg, catalogPkg), upstreamMatcher)

	applicable, err := applicableForDistro(provider, rp, searchPkg, pkgVersion)
	if err != nil {
		return nil, nil, err
	}

	// one split over every name's records: a fix a stream published under one name resolves a
	// disclosure stored under another, which splitting per name cannot see
	vulnerable, notVulnerable = applicable.SplitVulnerable(pkgVersion)
	return vulnerable, notVulnerable, nil
}

// FindResultsByDistroAcrossUpstreams searches the distro feed for searchPkg and for every package it
// was built from, then splits the union once.
//
// Searching each name and splitting each result separately cannot see across them, and the release
// streams do: a package can carry a disclosure under its own name in one stream while the fix that
// answers it is recorded under its source name in another. Both have to be in one split for the more
// specific stream to decide.
//
// The upstream packages are searched at their own versions, which are not always the binary's; the
// version each record was found at travels on its match details, so the single split still compares
// every record against the version its own search was made with.
//
// catalogPkg is the package matches are attributed to, for callers that search with a package that
// is not the one cataloged (rpm patches a missing epoch into the version it searches with, which
// must not reach the reported match); nil attributes them to searchPkg.
func FindResultsByDistroAcrossUpstreams(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) (vulnerable result.Set, notVulnerable result.Set, err error) {
	if searchPkg.Distro == nil {
		return result.Set{}, result.Set{}, nil
	}

	// the provider is built from the package as cataloged, so matches are attributed to it and the
	// upstream searches read as indirect
	rp := result.NewProvider(provider, matchPackage(searchPkg, catalogPkg), upstreamMatcher)

	// the version every record is ultimately compared against, for the records that do not name the
	// version their own search was made with. An unknown version yields one that satisfies nothing,
	// which is the point: it still carries the ecosystem's format and comparison config for the
	// records that do name their own version (see result.Set.SplitVulnerable).
	pkgVersion := distroVersion(searchPkg, cfg)

	applicable := result.Set{}
	if isUnknownVersion(searchPkg.Version) {
		// nothing can be said about this package's own version, but its upstreams carry versions of
		// their own -- an rpm whose sourceRPM names a release the binary's metadata does not -- and
		// those are still worth searching
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
	} else {
		applicable, err = applicableForDistro(provider, rp, searchPkg, pkgVersion)
		if err != nil {
			return nil, nil, err
		}
	}

	for _, upstreamPkg := range pkg.UpstreamPackages(searchPkg) {
		if upstreamPkg.Distro == nil || isUnknownVersion(upstreamPkg.Version) {
			continue
		}

		found, err := applicableForDistro(provider, rp, upstreamPkg, distroVersion(upstreamPkg, cfg))
		if err != nil {
			return nil, nil, err
		}
		applicable = applicable.Merge(found.MarkIndirect())
	}

	vulnerable, notVulnerable = applicable.SplitVulnerable(pkgVersion)
	return vulnerable, notVulnerable, nil
}

// applicableForDistro collects every record bearing on one search package, over every name the
// provider claims for it. For most packages that's just one name; rootio packages fan out to the
// bare upstream name so we find disclosures stored without the rootio prefix.
func applicableForDistro(provider vulnerability.Provider, rp result.Provider, searchPkg pkg.Package, pkgVersion *version.Version) (result.Set, error) {
	applicable := result.Set{}
	for _, name := range provider.PackageSearchNames(searchPkg) {
		v, err := rp.FindAll(
			search.ByPackageName(name),
			search.ByDistro(*searchPkg.Distro),
			OnlyQualifiedPackages(searchPkg),
			search.WithVersion(*pkgVersion),
		)
		if err != nil {
			return nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", searchPkg.Distro, name, err)
		}
		applicable = applicable.Merge(v)
	}
	return applicable, nil
}

func distroVersion(p pkg.Package, cfg *version.ComparisonConfig) *version.Version {
	if cfg != nil {
		return version.NewWithConfig(p.Version, pkg.VersionFormat(p), *cfg)
	}
	return version.New(p.Version, pkg.VersionFormat(p))
}

// MatchPackageByDistroAcrossUpstreams is the []match.Match form of FindResultsByDistroAcrossUpstreams.
func MatchPackageByDistroAcrossUpstreams(provider vulnerability.Provider, p pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) ([]match.Match, []match.IgnoreFilter, error) {
	vulnerable, notVulnerable, err := FindResultsByDistroAcrossUpstreams(provider, p, nil, upstreamMatcher, cfg)
	if err != nil {
		return nil, nil, err
	}

	return vulnerable.ToMatches(), OwnershipIgnores(p, "DistroPackageFixed", notVulnerable.Vulnerabilities()...), nil
}

// MatchPackageByDistro is a thin wrapper over FindResultsByDistro for callers that work in
// []match.Match: the vulnerable records become matches, and everything the split set aside becomes
// ignores the matcher applies to packages this one owns files for (e.g. an APK that owns NPM).
func MatchPackageByDistro(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) ([]match.Match, []match.IgnoreFilter, error) {
	vulnerable, notVulnerable, err := FindResultsByDistro(provider, searchPkg, catalogPkg, upstreamMatcher, cfg)
	if err != nil {
		return nil, nil, err
	}

	// Use the SBOM package (not the synthetic upstream) for file ownership — the upstream package doesn't have file metadata.
	ignores := OwnershipIgnores(matchPackage(searchPkg, catalogPkg), "DistroPackageFixed", notVulnerable.Vulnerabilities()...)

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
