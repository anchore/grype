package search

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

//nolint:funlen
func ByPackageDistro(store vulnerability.ProviderByDistro, d *distro.Distro, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, error) {
	if d == nil {
		return nil, nil
	}

	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil
	}

	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		if errors.Is(err, version.ErrUnsupportedVersion) {
			log.WithFields("error", err).Tracef("skipping package '%s@%s'", p.Name, p.Version)
			return nil, nil
		}
		return nil, fmt.Errorf("matcher failed to parse version pkg=%q ver=%q: %w", p.Name, p.Version, err)
	}

	var allPkgVulns []vulnerability.Vulnerability
	if v6provider, ok := store.(db.VulnerabilityProvider); ok {
		allPkgVulns, err = v6provider.FindVulnerabilities(db.DistroCriteria(p, d))
	} else {
		allPkgVulns, err = store.GetByDistro(d, p)
	}

	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", d, p.Name, err)
	}

	applicableVulns, err := onlyQualifiedPackages(d, p, allPkgVulns)
	if err != nil {
		return nil, fmt.Errorf("unable to filter distro-related vulnerabilities: %w", err)
	}

	// TODO: Port this over to a qualifier and remove
	applicableVulns, err = onlyVulnerableVersions(verObj, applicableVulns)
	if err != nil {
		return nil, fmt.Errorf("unable to filter distro-related vulnerabilities: %w", err)
	}

	var matches []match.Match
	for _, vuln := range applicableVulns {
		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:    match.ExactDirectMatch,
					Matcher: upstreamMatcher,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
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

	return matches, err
}

func isUnknownVersion(v string) bool {
	return v == "" || strings.ToLower(v) == "unknown"
}
