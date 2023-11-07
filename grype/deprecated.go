package grype

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
)

// TODO: deprecated, will remove before v1.0.0
func FindVulnerabilities(store store.Store, userImageStr string, scopeOpt source.Scope, registryOptions *image.RegistryOptions) (match.Matches, pkg.Context, []pkg.Package, error) {
	providerConfig := pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions:   registryOptions,
			CatalogingOptions: cataloger.DefaultConfig(),
		},
	}
	providerConfig.CatalogingOptions.Search.Scope = scopeOpt

	packages, context, _, err := pkg.Provide(userImageStr, providerConfig)
	if err != nil {
		return match.Matches{}, pkg.Context{}, nil, err
	}

	matchers := matcher.NewDefaultMatchers(matcher.Config{})

	return FindVulnerabilitiesForPackage(store, context.Distro, matchers, packages), context, packages, nil
}

// TODO: deprecated, will remove before v1.0.0
func FindVulnerabilitiesForPackage(store store.Store, d *linux.Release, matchers []matcher.Matcher, packages []pkg.Package) match.Matches {
	runner := VulnerabilityMatcher{
		Store:          store,
		Matchers:       matchers,
		NormalizeByCVE: false,
	}

	actualResults, _, err := runner.FindMatches(packages, pkg.Context{
		Distro: d,
	})
	if err != nil || actualResults == nil {
		log.WithFields("error", err).Error("unable to find vulnerabilities")
		return match.NewMatches()
	}
	return *actualResults
}
