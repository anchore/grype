package internal

import (
	"errors"
	"fmt"

	"github.com/facebookincubator/nvdtools/wfn"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/cpeversion"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

var ErrEmptyCPEMatch = errors.New("attempted CPE match against package with no CPEs")

// MatchPackageByCPEs retrieves all vulnerabilities that match any of the provided package's CPEs,
// returned as a flat slice of matches. It is a thin wrapper over FindResultsByCPEs for callers that
// work in []match.Match rather than result.Set.
func MatchPackageByCPEs(vulnProvider vulnerability.Provider, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	results, ignore, err := FindResultsByCPEs(vulnProvider, p, upstreamMatcher)
	if err != nil {
		return nil, nil, err
	}

	return results.ToMatches(), ignore, nil
}

// FindResultsByCPEs retrieves all vulnerabilities that match any of the provided package's CPEs as a
// result.Set, so callers can reconcile them against other sources by vulnerability identity. Records
// the CPE search finds but whose version is not affected are returned as "CPE not vulnerable" ignores.
//
//nolint:funlen
func FindResultsByCPEs(vulnProvider vulnerability.Provider, p pkg.Package, upstreamMatcher match.MatcherType) (result.Set, []match.IgnoreFilter, error) {
	provider := result.NewProvider(vulnProvider, p, upstreamMatcher)

	affected := result.Set{}
	var ignores []match.IgnoreFilter
	// Warn the user if they are matching by CPE, but there are no CPEs available.
	if len(p.CPEs) == 0 {
		return nil, nil, ErrEmptyCPEMatch
	}

	for _, c := range p.CPEs {
		// prefer the CPE version, but if npt specified use the package version
		searchVersion := c.Attributes.Version

		if p.Type == syftPkg.ApkPkg {
			searchVersion = cpeversion.Alpine(searchVersion)
		}

		if searchVersion == wfn.NA || searchVersion == wfn.Any || isUnknownVersion(searchVersion) {
			searchVersion = p.Version
		}

		if isUnknownVersion(searchVersion) {
			log.WithFields("package", p.Name).Trace("skipping package with unknown version")
			continue
		}

		// we should always show the exact CPE we searched by, not just what's in the component analysis (since we
		// may alter the version based on above processing)
		c.Attributes.Version = searchVersion

		format := pkg.VersionFormat(p)

		if format == version.JVMFormat {
			searchVersion = cpeversion.JVM(searchVersion, c.Attributes.Update)
		}

		var verObj *version.Version
		var err error
		if searchVersion != "" {
			verObj = version.New(searchVersion, format)
		}

		criteria := []vulnerability.Criteria{
			search.ByCPE(c),
			OnlyVulnerableTargets(p),
			OnlyQualifiedPackages(p),
			OnlyNonWithdrawnVulnerabilities(),
		}

		versionCriteria := OnlyVulnerableVersions(verObj)

		// find all vulnerability records in the DB for the given CPE (not including version comparisons)
		all, err := provider.FindResults(criteria...)
		if err != nil {
			return nil, nil, fmt.Errorf("matcher failed to fetch by CPE pkg=%q: %w", p.Name, err)
		}

		vulns := all.Filter(versionCriteria)

		unaffected, err := provider.FindResults(
			append(criteria, search.ForUnaffected(), versionCriteria)...,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("matcher failed to fetch unaffected CPE records for pkg=%q: %w", p.Name, err)
		}

		// add affected vulns to the top level set; nothing is reconciled until the set becomes matches
		affected = affected.Merge(vulns)
		// mark unaffected as ignores
		unaffected = all.Remove(vulns).Merge(unaffected)
		ignores = append(ignores, OwnershipIgnores(p, "CPE not vulnerable", unaffected.Vulnerabilities()...)...)
	}

	return affected, ignores, nil
}
