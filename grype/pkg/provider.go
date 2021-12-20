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
	for i := 0; i < len(packages); i++ {
		pkg := packages[i]
		for _, exclusion := range exclusions {
			for _, location := range pkg.Locations {
				matches, err := matchesLocation(exclusion, location)
				if err != nil {
					return nil, err
				}
				if matches {
					packages = append(packages[:i], packages[i+1:]...)
					i--
				}
			}
		}
	}
	return packages, nil
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
