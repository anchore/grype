package grype

import (
	"fmt"

	"github.com/anchore/grype/grype/db"

	"github.com/anchore/grype/grype/logger"

	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/result"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

func FindVulnerabilities(provider vulnerability.Provider, userImageStr string, scopeOpt scope.Option) (result.Result, *pkg.Catalog, *scope.Scope, error) {
	log.Info("Cataloging image")
	catalog, theScope, theDistro, err := syft.Catalog(userImageStr, scopeOpt)
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
			// we want to continue if possible even if we can't check for an update
			log.Errorf("unable to check for vulnerability database update")
			log.Debugf("check for vulnerability update failed: %+v", err)
		}
		if updateAvailable {
			log.Infof("Downloading new vulnerability DB")
			err = dbCurator.UpdateTo(updateEntry)
			if err != nil {
				return nil, fmt.Errorf("unable to update vulnerability database: %w", err)
			}
			log.Infof("Updated vulnerability DB to version=%d built=%q", updateEntry.Version, updateEntry.Built.String())
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
