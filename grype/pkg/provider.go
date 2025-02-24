package pkg

import (
	"errors"
	"fmt"

	"github.com/bmatcuk/doublestar/v2"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

var errDoesNotProvide = fmt.Errorf("cannot provide packages from the given source")

// Provide a set of packages and context metadata describing where they were sourced from.
func Provide(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	packages, ctx, s, err := syftSBOMProvider(userInput, config)
	if !errors.Is(err, errDoesNotProvide) {
		if len(config.Exclusions) > 0 {
			var exclusionsErr error
			packages, exclusionsErr = filterPackageExclusions(packages, config.Exclusions)
			if exclusionsErr != nil {
				return nil, ctx, s, exclusionsErr
			}
		}
		log.WithFields("input", userInput).Trace("interpreting input from the given SBOM")
		return packages, ctx, s, err
	}

	packages, ctx, s, err = purlProvider(userInput)
	if !errors.Is(err, errDoesNotProvide) {
		log.WithFields("input", userInput).Trace("interpreting input from the given PURL(s)")
		return packages, ctx, s, err
	}

	packages, ctx, s, err = cpeProvider(userInput)
	if !errors.Is(err, errDoesNotProvide) {
		log.WithFields("input", userInput).Trace("interpreting input from the given CPE")
		return packages, ctx, s, err
	}

	log.WithFields("input", userInput).Trace("passing input to syft for interpretation")
	return syftProvider(userInput, config)
}

// This will filter the provided packages list based on a set of exclusion expressions. Globs
// are allowed for the exclusions. A package will be *excluded* only if *all locations* match
// one of the provided exclusions.
func filterPackageExclusions(packages []Package, exclusions []string) ([]Package, error) {
	var out []Package
	for _, pkg := range packages {
		includePackage := true
		locations := pkg.Locations.ToSlice()
		if len(locations) > 0 {
			includePackage = false
			// require ALL locations to be excluded for the package to be excluded
		location:
			for _, location := range locations {
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
func locationMatches(location file.Location, exclusion string) (bool, error) {
	matchesRealPath, err := doublestar.Match(exclusion, location.RealPath)
	if err != nil {
		return false, err
	}
	matchesVirtualPath, err := doublestar.Match(exclusion, location.AccessPath)
	if err != nil {
		return false, err
	}
	return matchesRealPath || matchesVirtualPath, nil
}
