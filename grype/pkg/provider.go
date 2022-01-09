package pkg

import (
	"errors"
	"fmt"

	"github.com/bmatcuk/doublestar/v2"

	"github.com/anchore/syft/syft/source"
)

var errDoesNotProvide = fmt.Errorf("cannot provide packages from the given source")

// Provide a set of packages and context metadata describing where they were sourced from.
func Provide(userInput string, config ProviderConfig) ([]Package, Context, error) {
	packages, ctx, err := syftSBOMProvider(userInput)
	if !errors.Is(err, errDoesNotProvide) {
		if len(config.Exclusions) > 0 {
			packages, err = filterPackageExclusions(packages, config.Exclusions)
			if err != nil {
				return nil, ctx, err
			}
		}
		return packages, ctx, err
	}

	return syftProvider(userInput, config)
}

// This will filter the provided packages list based on a set of exclusion expressions. Globs
// are allowed for the exclusions. A package will be *excluded* only if *all locations* match
// one of the provided exclusions.
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
					match, err := locationMatches(location, exclusion)
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

// Test a location RealPath and VirtualPath for a match against the exclusion parameter.
// The exclusion allows glob expressions such as `/usr/**` or `**/*.json`. If the exclusion
// is an invalid pattern, an error is returned; otherwise, the resulting boolean indicates a match.
func locationMatches(location source.Location, exclusion string) (bool, error) {
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
