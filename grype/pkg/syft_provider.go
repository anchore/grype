package pkg

import (
	"context"
	"errors"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func syftProvider(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	src, err := getSource(userInput, config)
	if err != nil {
		return nil, Context{}, nil, err
	}

	defer func() {
		if src != nil {
			if err := src.Close(); err != nil {
				log.Tracef("unable to close source: %+v", err)
			}
		}
	}()

	s, err := syft.CreateSBOM(context.Background(), src, config.SBOMOptions)
	if err != nil {
		return nil, Context{}, nil, err
	}

	if s == nil {
		return nil, Context{}, nil, errors.New("no SBOM provided")
	}

	pkgCatalog := removePackagesByOverlap(s.Artifacts.Packages, s.Relationships, s.Artifacts.LinuxDistribution)

	srcDescription := src.Describe()

	packages := FromCollection(pkgCatalog, config.SynthesisConfig)
	pkgCtx := Context{
		Source: &srcDescription,
		Distro: s.Artifacts.LinuxDistribution,
	}

	return packages, pkgCtx, s, nil
}

func getSource(userInput string, config ProviderConfig) (source.Source, error) {
	if config.SBOMOptions.Search.Scope == "" {
		return nil, errDoesNotProvide
	}

	detection, err := source.Detect(userInput, source.DetectConfig{
		DefaultImageSource: config.DefaultImagePullSource,
	})
	if err != nil {
		return nil, err
	}

	var platform *image.Platform
	if config.Platform != "" {
		platform, err = image.NewPlatform(config.Platform)
		if err != nil {
			return nil, err
		}
	}

	return detection.NewSource(source.DetectionSourceConfig{
		Alias: source.Alias{
			Name: config.Name,
		},
		RegistryOptions: config.RegistryOptions,
		Platform:        platform,
		Exclude: source.ExcludeConfig{
			Paths: config.Exclusions,
		},
	})
}
