package search

import (
	"errors"
	"fmt"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/vulnerability"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/internal/log"
)

func ByDistro(p pkg.Package, d *distro.Distro) Criteria {
	return func(r Resources) ([]match.Match, error) {
		return byDistro(r, d, p)
	}
}

func byDistro(r Resources, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	if d == nil {
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

	d.MajorVersion()

	affectedPkgHandles, err := r.Store.GetPackageByNameAndDistro(p.Name, d.Name(), d.MajorVersion(), d.MinorVersion())
	if err != nil {
		return nil, fmt.Errorf("unable to fetch affected package: %w", err)
	}

	affectedPkgHandles, err = onlyQualifiedAffectedPackages(d, p, affectedPkgHandles)
	if err != nil {
		return nil, fmt.Errorf("unable to filter distro-related vulnerabilities by package qualifier: %w", err)
	}

	// TODO: Port this over to a qualifier and remove
	affectedPkgHandles, err = onlyWithinAffectedVersionRange(verObj, affectedPkgHandles)
	if err != nil {
		return nil, fmt.Errorf("unable to filter distro-related vulnerabilities by version range: %w", err)
	}

	var matches []match.Match
	for _, a := range affectedPkgHandles {

		vuln, err := r.Store.GetVulnerability(a.VulnerabilityID)
		if err != nil {
			// TODO: this is exposing DB id's to the user, which is not ideal even for logging
			return nil, fmt.Errorf("unable to fetch vulnerability %q: %w", a.VulnerabilityID, err)
		}

		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:    match.ExactDirectMatch,
					Matcher: r.AttributedMatcher,
					// TODO: codify these...
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


func toVulnerability(a v6.AffectedPackageHandle, h v6.VulnerabilityHandle) (*vulnerability.Vulnerability, error) {
	if h.BlobValue == nil {
		return nil, nil
	}

	if a.BlobValue == nil {
		return nil, nil
	}

	b := h.BlobValue

	return &vulnerability.Vulnerability{
		Constraint:             a.,
		PackageQualifiers:      nil,
		CPEs:                   nil,
		ID:                     "",
		Namespace:              "",
		Fix:                    vulnerability.Fix{},
		Advisories:             nil,
		RelatedVulnerabilities: nil,
	}, nil

}