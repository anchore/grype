package pkg

import (
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/pkg/cataloger"
)

type ProviderConfig struct {
	RegistryOptions   *image.RegistryOptions
	Exclusions        []string
	CatalogingOptions cataloger.Config
}
