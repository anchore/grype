package pkg

import (
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func syftProvider(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	if config.CatalogingOptions.Search.Scope == "" {
		return nil, Context{}, nil, errDoesNotProvide
	}

	sourceInput, err := source.ParseInputWithName(userInput, config.Platform, config.Name, config.DefaultImagePullSource)
	if err != nil {
		return nil, Context{}, nil, err
	}

	src, cleanup, err := source.New(*sourceInput, config.RegistryOptions, config.Exclusions)
	if err != nil {
		return nil, Context{}, nil, err
	}
	defer cleanup()

	catalog, relationships, theDistro, err := syft.CatalogPackages(src, config.CatalogingOptions)
	if err != nil {
		return nil, Context{}, nil, err
	}

	catalog = removePackagesByOverlap(catalog, relationships)

	packages := FromCatalog(catalog, config.SynthesisConfig)
	context := Context{
		Source: &src.Metadata,
		Distro: theDistro,
	}

	sbom := &sbom.SBOM{
		Source:        src.Metadata,
		Relationships: relationships,
		Artifacts: sbom.Artifacts{
			PackageCatalog: catalog,
		},
	}

	return packages, context, sbom, nil
}
