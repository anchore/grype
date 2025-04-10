package internal

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/packageurl-go"
)

var ErrEmptyPURLMatch = errors.New("attempted PURL match against package with no PURL")

func MatchPackageByPURL(provider vulnerability.Provider, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, error) {
	if p.PURL == "" {
		return nil, ErrEmptyPURLMatch
	}

	purl, err := packageurl.FromString(p.PURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PURL for package=%q: %w", p.Name, err)
	}

	searchVersion := purl.Version
	format := version.FormatFromPkg(p)
	if format == version.JVMFormat {
		searchVersion = transformJvmVersion(searchVersion, "")
	}

	verObj, err := version.NewVersion(searchVersion, format)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg=%q ver=%q: %w", p.Name, p.Version, err)
	}

	// find all vulnerability records in the DB for the given PURL
	vulns, err := provider.FindVulnerabilities(
		search.ByPackageName(purl.Name),
		onlyVulnerableTargets(p),
		onlyQualifiedPackages(p),
		onlyVulnerableVersions(verObj),
		onlyNonWithdrawnVulnerabilities(),
	)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch by PURL pkg=%q: %w", p.Name, err)
	}

	var matches []match.Match
	for _, vuln := range vulns {
		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       p,
			Details: match.Details{{
				Matcher:    upstreamMatcher,
				Type:       match.PURLMatch,
				Confidence: 0.9, // TODO: this is hard coded for now
				SearchedBy: match.PURLParameters{
					Namespace: purl.Type,
					PURL:      p.PURL,
					Package: match.PackageParameter{
						Name:    purl.Name,
						Version: purl.Version,
					},
				},
				Found: match.PURLResult{
					VulnerabilityID:   vuln.ID,
					VersionConstraint: vuln.Constraint.String(),
					PURL:              p.PURL,
				},
			}},
		})
	}

	return matches, nil
}
