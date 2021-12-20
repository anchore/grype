package pkg

import (
	"errors"
	"fmt"
	"github.com/bmatcuk/doublestar/v2"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

var errDoesNotProvide = fmt.Errorf("cannot provide packages from the given source")

// Provide a set of packages and context metadata describing where they were sourced from.
func Provide(userInput string, scopeOpt source.Scope, registryOptions *image.RegistryOptions, exclusions ...string) ([]Package, Context, error) {
	packages, ctx, err := syftSBOMProvider(userInput)
	if !errors.Is(err, errDoesNotProvide) {
		if len(exclusions) > 0 {
			packages, err = filterPackageExclusions(packages, exclusions)
			if err != nil {
				return nil, ctx, err
			}
		}
		return packages, ctx, err
	}

	return syftProvider(userInput, scopeOpt, registryOptions, exclusions...)
}

func filterPackageExclusions(packages []Package, exclusions []string) ([]Package, error) {
	var out []Package
	for _, pkg := range packages {
		includePackage := true
		if len(pkg.Locations) > 0 {
			includePackage = false
			// require ALL locations to be excluded for the package to be excluded
		location:
			for _, location := range pkg.Locations {
				for _, exclusion := range exclusions {
					match, err := matchesLocation(exclusion, location)
					if err != nil {
						return nil, err
					}
					if match {
						continue location
					}
				}
				// if this point is reached, one location has not matched any exclusion, include the package
				includePackage = true
				break
			}
		}
		if includePackage {
			out = append(out, pkg)
		}
	}
	return out, nil
}

func matchesLocation(exclusion string, location source.Location) (bool, error) {
	matchesRealPath, err := doublestar.Match(exclusion, location.RealPath)
	if err != nil {
		return false, err
	}
	matchesVirtualPath, err := doublestar.Match(exclusion, location.VirtualPath)
	if err != nil {
		return false, err
	}
	return matchesRealPath || matchesVirtualPath, nil
}
