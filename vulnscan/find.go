package vulnscan

import (
	"github.com/anchore/imgbom/imgbom/os"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/matcher"
	"github.com/anchore/vulnscan/vulnscan/result"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

func FindAllVulnerabilities(store vulnerability.Provider, o os.OS, catalog *pkg.Catalog) result.Result {
	res := result.NewResult()
	for p := range catalog.Enumerate() {
		res.Merge(FindVulnerabilities(store, o, p))
	}
	return res
}

func FindVulnerabilities(store vulnerability.Provider, o os.OS, packages ...*pkg.Package) result.Result {
	res := result.NewResult()
	for _, p := range packages {
		res.Merge(matcher.FindMatches(store, o, p))
	}
	return res
}
