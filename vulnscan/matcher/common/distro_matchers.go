package common

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

func FindMatchesByPackageDistro(store vulnerability.ProviderByDistro, d distro.Distro, p *pkg.Package, matcherName string) ([]match.Match, error) {
	allPkgVulns, err := store.GetByDistro(d, p)
	if err != nil {
		return nil, fmt.Errorf("distro matcher failed to fetch distro='%s' pkg='%s': %w", d, p.Name, err)
	}

	matches, err := FindMatchesForPackage(allPkgVulns, p, matcherName)
	for idx := range matches {
		// explicitly set the search key to indicate a distro match
		matches[idx].SearchKey = fmt.Sprintf("distro=[%s] pkg=[%s:%s]", d, p.Name, p.Version)
	}
	return matches, err
}
