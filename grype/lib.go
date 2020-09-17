package grype

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/bus"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/grype/grype/db"

	"github.com/anchore/grype/grype/logger"

	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

func FindVulnerabilities(provider vulnerability.Provider, userImageStr string, scopeOpt scope.Option) (match.Matches, *pkg.Catalog, *scope.Scope, error) {
	catalog, theScope, theDistro, err := syft.Catalog(userImageStr, scopeOpt)
	if err != nil {
		return match.Matches{}, nil, nil, err
	}

	return FindVulnerabilitiesForCatalog(provider, *theDistro, catalog), catalog, theScope, nil
}

func FindVulnerabilitiesForCatalog(provider vulnerability.Provider, d distro.Distro, catalog *pkg.Catalog) match.Matches {
	packages := make([]*pkg.Package, 0)
	for p := range catalog.Enumerate() {
		packages = append(packages, p)
	}
	return FindVulnerabilitiesForPackage(provider, d, packages...)
}

func FindVulnerabilitiesForPackage(provider vulnerability.Provider, d distro.Distro, packages ...*pkg.Package) match.Matches {
	return matcher.FindMatches(provider, d, packages...)
}

func LoadVulnerabilityDb(cfg db.Config, update bool) (vulnerability.Provider, vulnerability.MetadataProvider, error) {
	dbCurator := db.NewCurator(cfg)

	if update {
		_, err := dbCurator.Update()
		if err != nil {
			return nil, nil, err
		}
	}

	store, err := dbCurator.GetStore()
	if err != nil {
		return nil, nil, err
	}

	return vulnerability.NewProviderFromStore(store), vulnerability.NewMetadataStoreProvider(store), nil
}

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
