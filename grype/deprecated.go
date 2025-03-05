package grype

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/source"
)

// TODO: deprecated, will remove before v1.0.0
func FindVulnerabilities(store vulnerability.Provider, userImageStr string, scopeOpt source.Scope, registryOptions *image.RegistryOptions) (match.Matches, pkg.Context, []pkg.Package, error) {
	providerConfig := pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions: registryOptions,
			SBOMOptions:     syft.DefaultCreateSBOMConfig(),
		},
	}
	providerConfig.SBOMOptions.Search.Scope = scopeOpt

	packages, context, _, err := pkg.Provide(userImageStr, providerConfig)
	if err != nil {
		return match.Matches{}, pkg.Context{}, nil, err
	}

	matchers := matcher.NewDefaultMatchers(matcher.Config{})

	return FindVulnerabilitiesForPackage(store, context.Distro, matchers, packages), context, packages, nil
}

// TODO: deprecated, will remove before v1.0.0
func FindVulnerabilitiesForPackage(store vulnerability.Provider, d *linux.Release, matchers []match.Matcher, packages []pkg.Package) match.Matches {
	exclusionProvider, _ := store.(match.ExclusionProvider) // TODO v5 is an exclusion provider, but v6 is not
	runner := VulnerabilityMatcher{
		VulnerabilityProvider: store,
		ExclusionProvider:     exclusionProvider,
		Matchers:              matchers,
		NormalizeByCVE:        false,
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
