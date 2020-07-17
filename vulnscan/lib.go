package vulnscan

import (
	"fmt"

	"github.com/anchore/vulnscan/vulnscan/db"

	"github.com/anchore/vulnscan/vulnscan/logger"

	"github.com/anchore/imgbom/imgbom"
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/vulnscan/internal/log"
	"github.com/anchore/vulnscan/vulnscan/matcher"
	"github.com/anchore/vulnscan/vulnscan/result"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

// note: lib name must be a single word, all lowercase
const LibraryName = "vulnscan"

func FindVulnerabilities(provider vulnerability.Provider, userImageStr string, scopeOpt scope.Option) (result.Result, *pkg.Catalog, *scope.Scope, error) {
	log.Info("Cataloging image")
	catalog, theScope, theDistro, err := imgbom.Catalog(userImageStr, scopeOpt)
	if err != nil {
		return result.Result{}, nil, nil, err
	}

	return FindVulnerabilitiesForCatalog(provider, *theDistro, catalog), catalog, theScope, nil
}

func FindVulnerabilitiesForCatalog(provider vulnerability.Provider, d distro.Distro, catalog *pkg.Catalog) result.Result {
	res := result.NewResult()
	for p := range catalog.Enumerate() {
		res.Merge(FindVulnerabilitiesForPackage(provider, d, p))
	}
	return res
}

func FindVulnerabilitiesForPackage(provider vulnerability.Provider, d distro.Distro, packages ...*pkg.Package) result.Result {
	res := result.NewResult()
	for _, p := range packages {
		res.Merge(matcher.FindMatches(provider, d, p))
	}
	return res
}

func LoadVulnerabilityDb(cfg db.Config, update bool) (vulnerability.Provider, error) {
	dbCurator, err := db.NewCurator(cfg)
	if err != nil {
		return nil, fmt.Errorf("could not curate database: %w", err)
	}

	if update {
		updateAvailable, updateEntry, err := dbCurator.IsUpdateAvailable()
		if err != nil {
			// TODO: should this be so fatal? we can certainly continue with a warning...
			return nil, fmt.Errorf("unable to check for vulnerability database update: %w", err)
		}
		if updateAvailable {
			err = dbCurator.UpdateTo(updateEntry)
			if err != nil {
				return nil, fmt.Errorf("unable to update vulnerability database: %w", err)
			}
		}
	}

	store, err := dbCurator.GetStore()
	if err != nil {
		return nil, err
	}

	return vulnerability.NewProviderFromStore(store), nil
}

func SetLogger(logger logger.Logger) {
	log.Log = logger
}
