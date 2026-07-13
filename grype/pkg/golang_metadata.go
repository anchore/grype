package pkg

import "github.com/anchore/syft/syft/pkg"

type GolangBinMetadata struct {
	BuildSettings     pkg.KeyValues `json:"goBuildSettings,omitempty" cyclonedx:"goBuildSettings"`
	GoCompiledVersion string        `json:"goCompiledVersion" cyclonedx:"goCompiledVersion"`
	Architecture      string        `json:"architecture" cyclonedx:"architecture"`
	H1Digest          string        `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
	MainModule        string        `json:"mainModule,omitempty" cyclonedx:"mainModule"`
	GoCryptoSettings  []string      `json:"goCryptoSettings,omitempty" cyclonedx:"goCryptoSettings"`

	// Symbols are the function symbols compiled into the binary, grouped by the import path of the package
	// that owns them; each value is the list of symbol names local to that package (import path prefix
	// stripped). Populated only when syft cataloged the binary with symbol capture enabled.
	Symbols map[string][]string `json:"symbols,omitempty"`
}

type GolangModMetadata struct {
	H1Digest string `json:"h1Digest,omitempty"`
}

type GolangSourceMetadata struct {
	H1Digest        string `json:"h1Digest,omitempty"`
	OperatingSystem string `json:"os,omitempty"`
	Architecture    string `json:"architecture,omitempty"`
	BuildTags       string `json:"buildTags,omitempty"`
	CgoEnabled      bool   `json:"cgoEnabled"`
}
