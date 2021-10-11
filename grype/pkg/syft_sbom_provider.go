package pkg

import (
	"fmt"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
)

func syftSBOMProvider(config providerConfig) ([]Package, Context, error) {
	reader, err := getSBOMReader(config)
	if err != nil {
		return nil, Context{}, err
	}

	catalog, srcMetadata, theDistro, formatOption, err := syft.Decode(reader)
	if err != nil {
		return nil, Context{}, fmt.Errorf("unable to decode sbom: %w", err)
	}
	if formatOption == format.UnknownOption {
		return nil, Context{}, errDoesNotProvide
	}

	return FromCatalog(catalog), Context{
		Source: srcMetadata,
		Distro: theDistro,
	}, nil
}
