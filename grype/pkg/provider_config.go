package pkg

import (
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/pkg/cataloger"
)

type ProviderConfig struct {
	SyftProviderConfig
	SynthesisConfig
}

type SyftProviderConfig struct {
	CatalogingOptions             cataloger.Config
	RegistryOptions               *image.RegistryOptions
	Platform                      string
	Exclusions                    []string
	AttestationPublicKey          string
	AttestationIgnoreVerification bool
}

type SynthesisConfig struct {
	GenerateMissingCPEs bool
}
