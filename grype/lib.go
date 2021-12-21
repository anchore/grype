package grype

import (
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/logger"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/source"
	"github.com/wagoodman/go-partybus"
)

func FindVulnerabilities(provider vulnerability.Provider, userImageStr string, scopeOpt source.Scope, registryOptions *image.RegistryOptions) (match.Matches, pkg.Context, []pkg.Package, error) {
	packages, context, err := pkg.Provide(userImageStr, scopeOpt, registryOptions, nil)
	if err != nil {
		return match.Matches{}, pkg.Context{}, nil, err
	}

	return FindVulnerabilitiesForPackage(provider, context.Distro, packages...), context, packages, nil
}

func FindVulnerabilitiesForPackage(provider vulnerability.Provider, d *distro.Distro, packages ...pkg.Package) match.Matches {
	return matcher.FindMatches(provider, d, packages...)
}

func LoadVulnerabilityDB(cfg db.Config, update bool) (vulnerability.Provider, vulnerability.MetadataProvider, *db.Status, error) {
	dbCurator, err := db.NewCurator(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	if update {
		_, err := dbCurator.Update()
		if err != nil {
			return nil, nil, nil, err
		}
	}

	store, err := dbCurator.GetStore()
	if err != nil {
		return nil, nil, nil, err
	}

	status := dbCurator.Status()

	return vulnerability.NewProviderFromStore(store), vulnerability.NewMetadataStoreProvider(store), &status, status.Err
}

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
