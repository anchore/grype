package pkg

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
	"github.com/mitchellh/go-homedir"
)

func syftProvider(config providerConfig) ([]Package, Context, error) {
	if config.scopeOpt == "" {
		return nil, Context{}, errDoesNotProvide
	}

	src, cleanup, err := source.New(config.userInput, config.registryOptions)
	if err != nil {
		return nil, Context{}, err
	}
	defer cleanup()

	catalog, theDistro, err := syft.CatalogPackages(src, config.scopeOpt)
	if err != nil {
		return nil, Context{}, err
	}

	return FromCatalog(catalog), Context{
		Source: &src.Metadata,
		Distro: theDistro,
	}, nil
}

func getSBOMReader(config providerConfig) (io.Reader, error) {
	if config.reader != nil {
		// the caller has explicitly indicated to use the given reader as input
		return config.reader, nil
	}

	if explicitlySpecifyingSBOM(config.userInput) {
		filepath := strings.TrimPrefix(config.userInput, "sbom:")

		sbom, err := openSbom(filepath)
		if err != nil {
			return nil, fmt.Errorf("unable to use specified SBOM: %w", err)
		}

		return sbom, nil
	}

	// as a last resort, see if the raw user input specified an SBOM file
	sbom, err := openSbom(config.userInput)
	if err == nil {
		return sbom, nil
	}

	// no usable SBOM is available
	return nil, errDoesNotProvide
}

func openSbom(path string) (*os.File, error) {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open SBOM: %w", err)
	}

	sbom, err := os.Open(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open SBOM: %w", err)
	}

	return sbom, nil
}

func explicitlySpecifyingSBOM(userInput string) bool {
	return strings.HasPrefix(userInput, "sbom:")
}
