package pkg

import (
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
)

func syftProvider(userInput string, scopeOpt source.Scope, registryOptions *image.RegistryOptions, exclusions []string) ([]Package, Context, error) {
	if scopeOpt == "" {
		return nil, Context{}, errDoesNotProvide
	}

	src, cleanup, err := source.New(userInput, registryOptions, exclusions)
	if err != nil {
		return nil, Context{}, err
	}
	defer cleanup()

	searchConfig := cataloger.DefaultConfig()
	searchConfig.Search.Scope = scopeOpt

	catalog, _, theDistro, err := syft.CatalogPackages(src, searchConfig)
	if err != nil {
		return nil, Context{}, err
	}

	return FromCatalog(catalog), Context{
		Source: &src.Metadata,
		Distro: theDistro,
	}, nil
}
