package pkg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/anchore/grype/internal"
	"github.com/anchore/syft/syft/source"
)

var errDoesNotProvide = fmt.Errorf("cannot provide packages from the given source")

type providerConfig struct {
	userInput string
	scopeOpt  *source.Scope
	reader    io.Reader
}

type provider func(cfg providerConfig) ([]Package, Context, error)

// Provide a set of packages and context metadata describing where they were sourced from.
func Provide(userInput string, scopeOpt source.Scope) ([]Package, Context, error) {
	providers := []provider{
		syftJSONProvider,
		syftProvider, // important: we should try syft last
	}

	// aggregate stdin into a buffer that can be used across multiple providers dynamically
	var previousStdin bytes.Buffer

	for _, p := range providers {
		cfg := providerConfig{
			userInput: userInput,
			scopeOpt:  &scopeOpt,
		}

		if internal.IsPipedInput() && userInput == "" {
			// this is a hint to all providers that there is already a reader available, don't try and derive one from user input
			// however, the user input may be useful in situations where the reader isn't provided

			// this reader is a combination of previous bytes read from stdin by other providers as well as what still is
			// available from stdin. The Tee reader is to ensure that any read bytes from stdin are preserved.
			cfg.reader = io.MultiReader(&previousStdin, io.TeeReader(os.Stdin, &previousStdin))
		}

		packages, ctx, err := p(cfg)
		if !errors.Is(err, errDoesNotProvide) {
			return packages, ctx, err
		}
	}

	return nil, Context{}, errDoesNotProvide
}
