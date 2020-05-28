package vulnscan

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/matcher"
	"github.com/anchore/vulnscan/vulnscan/result"
)

func FindAllVulnerabilities(store match.Store, catalog *pkg.Catalog) result.Result {
	res := result.NewResult()
	for p := range catalog.Enumerate() {
		res.Merge(FindVulnerabilities(store, p))
	}
	return res
}

func FindVulnerabilities(store match.Store, packages ...pkg.Package) result.Result {
	res := result.NewResult()
	for _, p := range packages {
		res.Merge(matcher.FindMatches(store, p))
	}
	return res
}
