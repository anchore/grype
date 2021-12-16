package pkg

import (
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
)

func syftProvider(userInput string, scopeOpt source.Scope, registryOptions *image.RegistryOptions, excludes ...string) ([]Package, Context, error) {
	if scopeOpt == "" {
		return nil, Context{}, errDoesNotProvide
	}

	src, cleanup, err := source.New(userInput, registryOptions, excludes...)
	if err != nil {
		return nil, Context{}, err
	}
	defer cleanup()

	catalog, _, theDistro, err := syft.CatalogPackages(src, scopeOpt)
	if err != nil {
		return nil, Context{}, err
	}

	return FromCatalog(catalog), Context{
		Source: &src.Metadata,
		Distro: theDistro,
	}, nil
}
