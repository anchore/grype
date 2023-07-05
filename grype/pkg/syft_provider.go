package pkg

import (
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func syftProvider(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	if config.CatalogingOptions.Search.Scope == "" {
		return nil, Context{}, nil, errDoesNotProvide
	}

	detection, err := source.Detect(userInput, source.DetectConfig{
		DefaultImageSource: config.DefaultImagePullSource,
	})
	if err != nil {
		return nil, Context{}, nil, err
	}

	var platform *image.Platform
	if config.Platform != "" {
		platform, err = image.NewPlatform(config.Platform)
		if err != nil {
			return nil, Context{}, nil, err
		}
	}

	src, err := detection.NewSource(source.DetectionSourceConfig{
		Alias: source.Alias{
			Name: config.Name,
		},
		RegistryOptions: config.RegistryOptions,
		Platform:        platform,
		Exclude: source.ExcludeConfig{
			Paths: config.Exclusions,
		},
	})

	defer src.Close()

	catalog, relationships, theDistro, err := syft.CatalogPackages(src, config.CatalogingOptions)
	if err != nil {
		return nil, Context{}, nil, err
	}

	catalog = removePackagesByOverlap(catalog, relationships)

	srcDescription := src.Describe()

	packages := FromCollection(catalog, config.SynthesisConfig)
	context := Context{
		Source: &srcDescription,
		Distro: theDistro,
	}

	sbom := &sbom.SBOM{
		Source:        srcDescription,
		Relationships: relationships,
		Artifacts: sbom.Artifacts{
			Packages: catalog,
		},
	}

	return packages, context, sbom, nil
}
