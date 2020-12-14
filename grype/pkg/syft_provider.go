package pkg

import (
	"github.com/anchore/syft/syft"
)

func syftProvider(config providerConfig) ([]Package, Context, error) {
	if config.scopeOpt == nil {
		return nil, Context{}, errDoesNotProvide
	}

	theSource, catalog, theDistro, err := syft.Catalog(config.userInput, *config.scopeOpt)
	if err != nil {
		return nil, Context{}, err
	}

	return FromCatalog(catalog), Context{
		Source: &theSource.Metadata,
		Distro: theDistro,
	}, nil
}
