package common

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

func FindMatchesByPackageLanguage(store vulnerability.ProviderByLanguage, l pkg.Language, p *pkg.Package, matcherName string) ([]match.Match, error) {
	allPkgVulns, err := store.GetByLanguage(l, p)
	if err != nil {
		return nil, fmt.Errorf("language matcher failed to fetch language='%s' pkg='%s': %w", l, p.Name, err)
	}

	matches, err := FindMatchesForPackage(allPkgVulns, p, matcherName)
	for idx := range matches {
		// explicitly set the search key to indicate a language match
		matches[idx].SearchKey = fmt.Sprintf("language=[%s] pkg=[%s:%s]", l, p.Name, p.Version)
	}
	return matches, err
}
