package internal

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/internal/ignorereasons"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// FindResultsByDistro searches the distro feed under every name the provider claims for p and splits
// the union once (see SplitVulnerable), so a rootio NAK under `rootio-libssl3` denies a disclosure
// under `libssl3`.
func FindResultsByDistro(provider vulnerability.Provider, p pkg.Package, matcherType match.MatcherType, cfg *version.ComparisonConfig) (vulnerable, notVulnerable result.Set, err error) {
	return findResultsByDistro(provider, p, p, nil, matcherType, cfg)
}

// FindResultsByDistroAcrossUpstreams is FindResultsByDistro that also searches searchPkg's upstream
// (source) packages in the same split, so a fix under the source name resolves a disclosure under
// the binary name.
//
// target is the package matches are attributed to when it differs from searchPkg (e.g. an rpm
// searched with an explicit epoch); nil attributes them to searchPkg.
func FindResultsByDistroAcrossUpstreams(provider vulnerability.Provider, searchPkg pkg.Package, target *pkg.Package, matcherType match.MatcherType, cfg *version.ComparisonConfig) (vulnerable, notVulnerable result.Set, err error) {
	return findResultsByDistro(provider, searchPkg, matchPackage(searchPkg, target), pkg.UpstreamPackages(searchPkg), matcherType, cfg)
}

func findResultsByDistro(provider vulnerability.Provider, searchPkg, target pkg.Package, upstreams []pkg.Package, matcherType match.MatcherType, cfg *version.ComparisonConfig) (vulnerable, notVulnerable result.Set, err error) {
	if searchPkg.Distro == nil {
		return result.Set{}, result.Set{}, nil
	}

	rp := result.NewProvider(provider, target, matcherType)

	applicable := result.Set{}
	if isUnknownVersion(searchPkg.Version) {
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
	} else {
		applicable, err = applicableForDistro(provider, rp, searchPkg)
		if err != nil {
			return nil, nil, err
		}
	}

	for _, upstreamPkg := range upstreams {
		if upstreamPkg.Distro == nil || isUnknownVersion(upstreamPkg.Version) {
			continue
		}

		// indirect even when the upstream has the package's own name
		found, err := applicableForDistro(provider, rp, upstreamPkg, search.BySourcePackage())
		if err != nil {
			return nil, nil, err
		}
		applicable = applicable.Merge(found)
	}

	vulnerable, notVulnerable = SplitVulnerable(applicable, distroVersion(searchPkg, cfg))
	return vulnerable, notVulnerable, nil
}

// applicableForDistro collects every record for each name the provider claims for searchPkg, with any
// extra criteria (e.g. search.BySourcePackage).
func applicableForDistro(provider vulnerability.Provider, rp result.Provider, searchPkg pkg.Package, extra ...vulnerability.Criteria) (result.Set, error) {
	applicable := result.Set{}
	for _, name := range provider.PackageSearchNames(searchPkg) {
		searched := searchPkg
		searched.Name = name
		v, err := rp.FindAll(append([]vulnerability.Criteria{
			search.ByPackageName(name),
			search.ByDistro(*searchPkg.Distro),
			OnlyQualifiedPackages(searchPkg),
			search.WithPackage(searched),
		}, extra...)...)
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

// MatchPackageByDistro is the []match.Match form of FindResultsByDistro.
func MatchPackageByDistro(provider vulnerability.Provider, p pkg.Package, matcherType match.MatcherType, cfg *version.ComparisonConfig) ([]match.Match, []match.IgnoreFilter, error) {
	vulnerable, notVulnerable, err := FindResultsByDistro(provider, p, matcherType, cfg)
	if err != nil {
		return nil, nil, err
	}
	return vulnerable.ToMatches(p), OwnershipIgnores(p, ignorereasons.DistroFixed, notVulnerable.Vulnerabilities()...), nil
}

// MatchPackageByDistroAcrossUpstreams is the []match.Match form of FindResultsByDistroAcrossUpstreams.
func MatchPackageByDistroAcrossUpstreams(provider vulnerability.Provider, p pkg.Package, matcherType match.MatcherType, cfg *version.ComparisonConfig) ([]match.Match, []match.IgnoreFilter, error) {
	vulnerable, notVulnerable, err := FindResultsByDistroAcrossUpstreams(provider, p, nil, matcherType, cfg)
	if err != nil {
		return nil, nil, err
	}
	return vulnerable.ToMatches(p), OwnershipIgnores(p, ignorereasons.DistroFixed, notVulnerable.Vulnerabilities()...), nil
}

func matchPackage(searchPkg pkg.Package, target *pkg.Package) pkg.Package {
	if target != nil {
		return *target
	}
	return searchPkg
}

func isUnknownVersion(v string) bool {
	return strings.ToLower(v) == "unknown"
}
