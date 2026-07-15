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
	// stripped). Populated only when syft cataloged the binary with symbol capture enabled. Used solely
	// for symbol-scoped vulnerability matching and intentionally not serialized: the raw symbol lists are
	// large (thousands of entries per binary) and not useful in the report output.
	//
	// Names are normalized to govulndb's convention when the package is built by the provider:
	// pointer-receiver decoration, generic type parameters, and the "-fm" method-value suffix are
	// stripped. The gosymbols qualifier relies on this normalization having already happened, so a value
	// assembled by hand (rather than via the provider) must supply already-normalized names to match.
	Symbols map[string][]string `json:"-"`
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
