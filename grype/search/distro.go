package search

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func MatchesByPackageDistro(store vulnerability.ProviderByDistro, d *distro.Distro, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, error) {
	if d == nil {
		return nil, nil
	}

	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
	}

	var allPkgVulns []vulnerability.Vulnerability

	allPkgVulns, err = store.GetByDistro(d, p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch distro='%s' pkg='%s': %w", d, p.Name, err)
	}

	matches := make([]match.Match, 0)
	for _, vuln := range allPkgVulns {
		// if the constraint it met, then the given package has the vulnerability
		isPackageVulnerable, err := vuln.Constraint.Satisfied(verObj)
		if err != nil {
			var e *version.NonFatalConstraintError
			if errors.As(err, &e) {
				log.Warn(e)
			} else {
				return nil, fmt.Errorf("distro matcher failed to check constraint='%s' version='%s': %w", vuln.Constraint, verObj, err)
			}
		}

		if !isPackageVulnerable {
			continue
		}

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
						"versionConstraint": vuln.Constraint.String(),
					},
					Confidence: 1.0, // TODO: this is hard coded for now
				},
			},
		})
	}

	return matches, err
}
