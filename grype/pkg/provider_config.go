package pkg

import (
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
)

type ProviderConfig struct {
	SyftProviderConfig
	SynthesisConfig
}

type SyftProviderConfig struct {
	SBOMOptions            *syft.CreateSBOMConfig
	RegistryOptions        *image.RegistryOptions
	Platform               string
	Exclusions             []string
	Name                   string
	DefaultImagePullSource string
}

type SynthesisConfig struct {
	GenerateMissingCPEs bool
}
