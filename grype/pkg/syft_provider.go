package pkg

import (
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
)

func syftProvider(config providerConfig) ([]Package, Context, error) {
	if config.scopeOpt == "" {
		return nil, Context{}, errDoesNotProvide
	}

	src, cleanup, err := source.New(config.userInput, config.registryOptions)
	if err != nil {
		return nil, Context{}, err
	}
	defer cleanup()

	catalog, theDistro, err := syft.CatalogPackages(src, config.scopeOpt)
	if err != nil {
		return nil, Context{}, err
	}

	return FromCatalog(catalog), Context{
		Source: &src.Metadata,
		Distro: theDistro,
	}, nil
}
