package pkg

import (
	"errors"
	"fmt"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

var errDoesNotProvide = fmt.Errorf("cannot provide packages from the given source")

// Provide a set of packages and context metadata describing where they were sourced from.
func Provide(userInput string, scopeOpt source.Scope, registryOptions *image.RegistryOptions, exclusions ...string) ([]Package, Context, error) {
	packages, ctx, err := syftSBOMProvider(userInput)
	if !errors.Is(err, errDoesNotProvide) {
		return packages, ctx, err
	}

	return syftProvider(userInput, scopeOpt, registryOptions, exclusions...)
}
