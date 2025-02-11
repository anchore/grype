package internal

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func MatchPackageByDistro(store vulnerability.Provider, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, []match.IgnoredMatch, error) {
	if p.Distro == nil {
		return nil, nil, nil
	}

	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		if errors.Is(err, version.ErrUnsupportedVersion) {
			log.WithFields("error", err).Tracef("skipping package '%s@%s'", p.Name, p.Version)
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("matcher failed to parse version pkg=%q ver=%q: %w", p.Name, p.Version, err)
	}

	var matches []match.Match
	vulns, err := store.FindVulnerabilities(
		search.ByPackageName(p.Name),
		search.ByDistro(*p.Distro),
		onlyQualifiedPackages(p),
		onlyVulnerableVersions(verObj),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", p.Distro, p.Name, err)
	}

	for _, vuln := range vulns {
		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:    match.ExactDirectMatch,
					Matcher: upstreamMatcher,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    p.Distro.Type.String(),
							"version": p.Distro.RawVersion,
						},
						// why include the package information? The given package searched with may be a source package
						// for another package that is installed on the system. This makes it apparent exactly what
						// was used in the search.
						"package": map[string]string{
							"name":    p.Name,
							"version": p.Version,
						},
						"namespace": vuln.Namespace,
					},
					Found: map[string]interface{}{
						"vulnerabilityID":   vuln.ID,
						"versionConstraint": vuln.Constraint.String(),
					},
					Confidence: 1.0, // TODO: this is hard coded for now
				},
			},
		})
	}
	return matches, nil, err
}

func isUnknownVersion(v string) bool {
	return v == "" || strings.ToLower(v) == "unknown"
}
