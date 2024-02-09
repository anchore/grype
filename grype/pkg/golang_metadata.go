package pkg

import "github.com/anchore/syft/syft/pkg"

type GolangBinMetadata struct {
	BuildSettings     pkg.KeyValues `json:"goBuildSettings,omitempty" cyclonedx:"goBuildSettings"`
	GoCompiledVersion string        `json:"goCompiledVersion" cyclonedx:"goCompiledVersion"`
	Architecture      string        `json:"architecture" cyclonedx:"architecture"`
	H1Digest          string        `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
	MainModule        string        `json:"mainModule,omitempty" cyclonedx:"mainModule"`
	GoCryptoSettings  []string      `json:"goCryptoSettings,omitempty" cyclonedx:"goCryptoSettings"`
}

type GolangModMetadata struct {
	H1Digest string `json:"h1Digest,omitempty"`
}
