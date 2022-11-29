package grype

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
)

// TODO: deprecated, remove in v1.0.0
func FindVulnerabilities(store store.Store, userImageStr string, scopeOpt source.Scope, registryOptions *image.RegistryOptions) (match.Matches, pkg.Context, []pkg.Package, error) {
	providerConfig := pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions:   registryOptions,
			CatalogingOptions: cataloger.DefaultConfig(),
		},
	}
	providerConfig.CatalogingOptions.Search.Scope = scopeOpt

	packages, context, err := pkg.Provide(userImageStr, providerConfig)
	if err != nil {
		return match.Matches{}, pkg.Context{}, nil, err
	}

	matchers := matcher.NewDefaultMatchers(matcher.Config{})

	return FindVulnerabilitiesForPackage(store, context.Distro, matchers, packages), context, packages, nil
}

// TODO: deprecated, remove in v1.0.0
func FindVulnerabilitiesForPackage(store store.Store, d *linux.Release, matchers []matcher.Matcher, packages []pkg.Package) match.Matches {
	return matcher.FindMatches(store, d, matchers, packages)
}
