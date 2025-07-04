package pkg

import (
	"context"
	"errors"

	"github.com/anchore/go-collections"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/sourceproviders"
)

func syftProvider(userInput string, config ProviderConfig, applyChannel func(*distro.Distro)) ([]Package, Context, *sbom.SBOM, error) {
	src, err := getSource(userInput, config)
	if err != nil {
		return nil, Context{}, nil, err
	}
	defer log.CloseAndLogError(src, "syft source")

	s, err := syft.CreateSBOM(context.Background(), src, config.SBOMOptions)
	if err != nil {
		return nil, Context{}, nil, err
	}

	if s == nil {
		return nil, Context{}, nil, errors.New("no SBOM provided")
	}

	srcDescription := src.Describe()

	var d *distro.Distro
	if config.Distro.Override != nil {
		d = config.Distro.Override
	} else {
		d = distro.FromRelease(s.Artifacts.LinuxDistribution)
		applyChannel(d)
	}

	pkgCatalog := removePackagesByOverlap(s.Artifacts.Packages, s.Relationships, d)

	packages := FromCollection(pkgCatalog, config.SynthesisConfig)
	pkgCtx := Context{
		Source: &srcDescription,
		Distro: d,
	}

	return packages, pkgCtx, s, nil
}

func getSource(userInput string, config ProviderConfig) (source.Source, error) {
	if config.SBOMOptions.Search.Scope == "" {
		return nil, errDoesNotProvide
	}

	var err error
	var platform *image.Platform
	if config.Platform != "" {
		platform, err = image.NewPlatform(config.Platform)
		if err != nil {
			return nil, err
		}
	}

	var sources []string
	schemeSource, newUserInput := stereoscope.ExtractSchemeSource(userInput, allSourceTags()...)
	if schemeSource != "" {
		sources = []string{schemeSource}
		userInput = newUserInput
	}

	return syft.GetSource(context.Background(), userInput, syft.DefaultGetSourceConfig().
		WithSources(sources...).
		WithDefaultImagePullSource(config.DefaultImagePullSource).
		WithAlias(source.Alias{Name: config.Name}).
		WithRegistryOptions(config.RegistryOptions).
		WithPlatform(platform).
		WithExcludeConfig(source.ExcludeConfig{Paths: config.Exclusions}))
}

func allSourceTags() []string {
	return collections.TaggedValueSet[source.Provider]{}.Join(sourceproviders.All("", nil)...).Tags()
}
