package pkg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/anchore/grype/internal/log"

	"github.com/anchore/grype/internal"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

var errDoesNotProvide = fmt.Errorf("cannot provide packages from the given source")

type providerConfig struct {
	userInput       string
	scopeOpt        source.Scope
	reader          io.Reader
	registryOptions *image.RegistryOptions
}

type provider func(cfg providerConfig) ([]Package, Context, error)

// Provide a set of packages and context metadata describing where they were sourced from.
func Provide(userInput string, scopeOpt source.Scope, registryOptions *image.RegistryOptions) ([]Package, Context, error) {
	providers := []provider{
		syftJSONProvider,
		syftProvider, // important: we should try syft last
	}

	// capture stdin bytes, so they can be used across multiple providers
	capturedStdin := bytesFromStdin()

	for _, provide := range providers {
		config := determineProviderConfig(userInput, scopeOpt, registryOptions, capturedStdin)

		packages, ctx, err := provide(config)
		if !errors.Is(err, errDoesNotProvide) {
			return packages, ctx, err
		}
	}

	return nil, Context{}, errDoesNotProvide
}

func bytesFromStdin() []byte {
	isPipedInput, err := internal.IsPipedInput()
	if err != nil {
		log.Warnf("unable to determine if there is piped input: %+v", err)
		isPipedInput = false
	}

	if isPipedInput {
		capturedStdin, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return nil
		}

		return capturedStdin
	}

	return nil
}

func determineProviderConfig(userInput string, scopeOpt source.Scope, registryOptions *image.RegistryOptions, stdin []byte) providerConfig {
	config := providerConfig{
		userInput:       userInput,
		scopeOpt:        scopeOpt,
		registryOptions: registryOptions,
	}

	if len(stdin) > 0 {
		config.reader = bytes.NewReader(stdin)
	}

	return config
}
