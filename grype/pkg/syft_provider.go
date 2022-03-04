package pkg

import (
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
)

func syftProvider(userInput string, config ProviderConfig) ([]Package, Context, error) {
	if config.CatalogingOptions.Search.Scope == "" {
		return nil, Context{}, errDoesNotProvide
	}

	src, cleanup, err := source.New(userInput, config.RegistryOptions, config.Exclusions)
	if err != nil {
		return nil, Context{}, err
	}
	defer cleanup()

	catalog, _, theDistro, err := syft.CatalogPackages(src, config.CatalogingOptions)
	if err != nil {
		return nil, Context{}, err
	}

	return FromCatalog(catalog, config), Context{
		Source: &src.Metadata,
		Distro: theDistro,
	}, nil
}
