package pkg

import (
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
)

func syftProvider(userInput string, config ProviderConfig) ([]Package, Context, error) {
	if config.CatalogingOptions.Search.Scope == "" {
		return nil, Context{}, errDoesNotProvide
	}

	si, err := source.ParseInput(userInput, true)
	if err != nil {
		return nil, Context{}, err
	}

	src, cleanup, err := source.New(*si, config.RegistryOptions, config.Exclusions)
	if err != nil {
		return nil, Context{}, err
	}
	defer cleanup()

	catalog, _, theDistro, err := syft.CatalogPackages(src, config.CatalogingOptions)
	if err != nil {
		return nil, Context{}, err
	}

	return FromCatalog(catalog), Context{
		Source: &src.Metadata,
		Distro: theDistro,
	}, nil
}
