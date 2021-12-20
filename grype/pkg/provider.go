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
			for i := 0; i < len(packages); i++ {
				pkg := packages[i]
				for _, exclusion := range exclusions {
					for _, location := range pkg.Locations {
						matchesRealPath, err := doublestar.Match(exclusion, location.RealPath)
						if err != nil {
							return nil, ctx, err
						}
						matchesVirtualPath, err := doublestar.Match(exclusion, location.VirtualPath)
						if err != nil {
							return nil, ctx, err
						}
						if matchesRealPath || matchesVirtualPath {
							packages = append(packages[:i], packages[i+1:]...)
							i--
						}
					}
				}
			}
		}
		return packages, ctx, err
	}

	return syftProvider(userInput, scopeOpt, registryOptions, exclusions...)
}
