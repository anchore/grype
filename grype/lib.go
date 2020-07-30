package grype

import (
	"fmt"

	"github.com/anchore/grype/internal/bus"
	"github.com/wagoodman/go-partybus"

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
	packages := make([]*pkg.Package, 0)
	for p := range catalog.Enumerate() {
		packages = append(packages, p)
	}
	return FindVulnerabilitiesForPackage(provider, d, packages...)
}

func FindVulnerabilitiesForPackage(provider vulnerability.Provider, d distro.Distro, packages ...*pkg.Package) result.Result {
	return matcher.FindMatches(provider, d, packages...)
}

func LoadVulnerabilityDb(cfg db.Config, update bool) (vulnerability.Provider, error) {
	dbCurator := db.NewCurator(cfg)

	if update {
		updateAvailable, updateEntry, err := dbCurator.IsUpdateAvailable()
		if err != nil {
			// we want to continue if possible even if we can't check for an update
			log.Infof("unable to check for vulnerability database update")
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

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
