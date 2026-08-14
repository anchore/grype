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

func syftProvider(userInput string, config ProviderConfig, applyChannel func(*distro.Distro)) ([]*Package, Context, *sbom.SBOM, error) {
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

	// a live source can be probed for distro identification marker files directly (this must run
	// before src's deferred Close). Resolver errors are logged and treated as "no marker" so the
	// probe never blocks a scan.
	var hasPath func(string) bool
	resolver, resolverErr := src.FileResolver(config.SBOMOptions.Search.Scope)
	if resolverErr != nil {
		log.WithFields("error", resolverErr).Trace("unable to acquire file resolver for distro identification marker checks")
	} else {
		hasPath = resolver.HasPath
	}

	d, distroDetectionFailed := distroFromSBOM(s, config, applyChannel, hasPath)

	packages := FromCollection(s.Artifacts.Packages, s.Relationships, config.SynthesisConfig)
	pkgCtx := Context{
		Source:                &srcDescription,
		Distro:                d,
		DistroDetectionFailed: distroDetectionFailed,
	}

	return packages, pkgCtx, s, nil
}

// distroFromSBOM derives the distro to match against. hasPath optionally probes the live source
// for distro-identification marker files; the SBOM's file catalog is always consulted as well
// (best effort — see sbomHasPath).
func distroFromSBOM(s *sbom.SBOM, config ProviderConfig, applyChannel func(*distro.Distro), hasPath func(string) bool) (d *distro.Distro, detectionFailed bool) {
	if config.Distro.Override != nil {
		d = config.Distro.Override
	} else {
		d = distro.FromRelease(s.Artifacts.LinuxDistribution, config.Distro.FixChannels)
		applyChannel(d)
		// source evidence (marker files, image labels) may indicate a vendor-curated derivative of
		// the detected distro; identifiers run after channels since a remapped distro replaces them
		probe := func(p string) bool {
			return (hasPath != nil && hasPath(p)) || sbomHasPath(s, p)
		}
		d = ApplyDistroIdentifiers(d, &s.Source, probe, config.Distro.Identifiers)
		// detection failed if we had linux release info but couldn't determine distro type
		detectionFailed = s.Artifacts.LinuxDistribution != nil && d == nil
	}
	return d, detectionFailed
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

	// prioritize explicitly specified sources from --from flag
	sources := config.Sources
	if len(sources) == 0 {
		// fallback to extracting from scheme if --from not specified (for backward compatibility)
		schemeSource, newUserInput := stereoscope.ExtractSchemeSource(userInput, allSourceTags()...)
		if schemeSource != "" {
			sources = []string{schemeSource}
			userInput = newUserInput
		}
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
