package apk

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/common"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []pkg.Type {
	return []pkg.Type{pkg.ApkPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.ApkMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d distro.Distro, p *pkg.Package) ([]match.Match, error) {
	var matches = make([]match.Match, 0)
	fixes := make(map[string]match.Match, 0)

	// create a slice of Alpine's sec db
	secDbFixes, err := FindFixesByPackageDistro(store, d, p, m.Type())
	if err != nil {
		return nil, err
	}

	for _, secDbFix := range secDbFixes {
		key := fmt.Sprintf("%s%s", secDbFix.Package.Name, secDbFix.Vulnerability.Constraint.String())
		fixes[key] = secDbFix
	}

	// NVD source
	cpeMatches, err := common.FindMatchesByPackageCPE(store, p, m.Type())
	if err != nil {
		return nil, err
	}
	for _, cpeMatch := range cpeMatches {
		key := fmt.Sprintf("%s%s", cpeMatch.Package.Name, cpeMatch.Package.Version)
		// check if the fix already exists, if it doesn't then this is a vulnerability
		if _, ok := fixes[key]; !ok {
			matches = append(matches, cpeMatch)
		}
	}

	return matches, nil
}

// FindFixesByPackageDistro retrieves all the fixes reported by Alpine - much unlike other distros that report vulnerabilities
func FindFixesByPackageDistro(store vulnerability.ProviderByDistro, d distro.Distro, p *pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, error) {
	// XXX this might need to be removed or adapted with an IF-ONLY-IF, perhaps FindMatchesByPackageDistro can be used as-is
	allPkgVulns, err := store.GetByDistro(d, p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch distro='%s' pkg='%s': %w", d, p.Name, err)
	}

	matches := make([]match.Match, 0)
	for _, vuln := range allPkgVulns {
		matches = append(matches, match.Match{
			Type:          match.ExactDirectMatch,
			Confidence:    1.0, // TODO: this is hard coded for now
			Vulnerability: *vuln,
			Package:       p,
			Matcher:       upstreamMatcher,
			SearchKey:     fmt.Sprintf("distro[%s] constraint[%s]", d, vuln.Constraint.String()),
		})
	}

	return matches, err
}
