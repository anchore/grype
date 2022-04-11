package grype

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/logger"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
)

func FindVulnerabilities(provider vulnerability.Provider, userImageStr string, scopeOpt source.Scope, registryOptions *image.RegistryOptions) (match.Matches, pkg.Context, []pkg.Package, error) {
	providerConfig := pkg.ProviderConfig{
		RegistryOptions:   registryOptions,
		CatalogingOptions: cataloger.DefaultConfig(),
	}
	providerConfig.CatalogingOptions.Search.Scope = scopeOpt

	packages, context, err := pkg.Provide(userImageStr, providerConfig)
	if err != nil {
		return match.Matches{}, pkg.Context{}, nil, err
	}

	matchers := matcher.NewDefaultMatchers(matcher.Config{})

	return FindVulnerabilitiesForPackage(provider, context.Distro, packages, matchers), context, packages, nil
}

func FindVulnerabilitiesForPackage(provider vulnerability.Provider, d *linux.Release, packages []pkg.Package, matchers []matcher.Matcher) match.Matches {
	return matcher.FindMatches(provider, d, packages, matchers)
}

func LoadVulnerabilityDB(cfg db.Config, update bool) (vulnerability.Provider, vulnerability.MetadataProvider, *db.Status, error) {
	dbCurator, err := db.NewCurator(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	if update {
		log.Debug("looking for updates on vulnerability database")
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

	return db.NewVulnerabilityProvider(store), db.NewVulnerabilityMetadataProvider(store), &status, status.Err
}

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
