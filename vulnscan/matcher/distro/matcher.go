package distro

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/version"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

type Matcher struct {
}

func (m *Matcher) Match(store vulnerability.Provider, o distro.Distro, p *pkg.Package) ([]match.Match, error) {
	// TODO: add other kinds of matches? fuzzy matches, etc...
	return m.ExactPackageNameMatch(store, o, p)
}

func (m *Matcher) ExactPackageNameMatch(store vulnerability.Provider, o distro.Distro, p *pkg.Package) ([]match.Match, error) {

	matches := make([]match.Match, 0)

	// TODO: there should be a vulnerability object in the vulnscan-db/db/vulnerability for mondel serialization and one here in vulnerability for rich objects

	allPkgVulns, err := store.GetByDistro(o, p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch distro='%s' pkg='%s': %w", o, p.Name, err)
	}

	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
	}

	for _, vuln := range allPkgVulns {
		// if the constraint it met, then the given package has the vulnerability
		satisfied, err := vuln.Constraint.Satisfied(verObj)
		if err != nil {
			// TODO: not enough information (cannot back track constraint object)
			return nil, fmt.Errorf("matcher failed to check constraint='%s' version='%s': %w", vuln.Constraint, verObj, err)
		}

		if satisfied {
			matches = append(matches, match.Match{
				Confidence:    1.0, // TODO: this is hard coded for now
				Vulnerability: *vuln,
				Package:       p,
				SearchKey:     fmt.Sprintf("%s:%s", p.Name, p.Version), // TODO: better way to signify exact match?
			})
		}
	}
	return matches, nil
}
