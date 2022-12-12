package grype

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/go-logger"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
)

// TODO: do we want this to return the SBOM used to generate the report
func FindVulnerabilities(store store.Store, userImageStr string, scopeOpt source.Scope, registryOptions *image.RegistryOptions) (match.Matches, pkg.Context, []pkg.Package, error) {
	providerConfig := pkg.ProviderConfig{
		RegistryOptions:   registryOptions,
		CatalogingOptions: cataloger.DefaultConfig(),
	}
	providerConfig.CatalogingOptions.Search.Scope = scopeOpt

	packages, context, _, err := pkg.Provide(userImageStr, providerConfig)
	if err != nil {
		return match.Matches{}, pkg.Context{}, nil, err
	}

	matchers := matcher.NewDefaultMatchers(matcher.Config{})

	return FindVulnerabilitiesForPackage(store, context.Distro, matchers, packages), context, packages, nil
}

func FindVulnerabilitiesForPackage(store store.Store, d *linux.Release, matchers []matcher.Matcher, packages []pkg.Package) match.Matches {
	return matcher.FindMatches(store, d, matchers, packages)
}

func LoadVulnerabilityDB(cfg db.Config, update bool) (*store.Store, *db.Status, *db.Closer, error) {
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

	storeReader, dbCloser, err := dbCurator.GetStore()
	if err != nil {
		return nil, nil, nil, err
	}

	status := dbCurator.Status()

	p, err := db.NewVulnerabilityProvider(storeReader)
	if err != nil {
		return nil, &status, nil, err
	}

	s := &store.Store{
		Provider:          p,
		MetadataProvider:  db.NewVulnerabilityMetadataProvider(storeReader),
		ExclusionProvider: db.NewMatchExclusionProvider(storeReader),
	}

	closer := &db.Closer{DBCloser: dbCloser}

	return s, &status, closer, nil
}

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
