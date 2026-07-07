package pkg

type RpmMetadata struct {
	Epoch           *int    `json:"epoch" cyclonedx:"epoch"`
	ModularityLabel *string `json:"modularityLabel" cyclonedx:"modularityLabel"`
	// Arch is the package's architecture in rpm's native spelling ("x86_64", "aarch64",
	// "noarch", ...), copied verbatim from the syft metadata. It is read at match time by
	// pkg/qualifier/architecture to match a package against the architecture a vulnerability
	// entry applies to. Cross-dialect aliases (amd64↔x86_64, ...) are reconciled there, so
	// this is intentionally a raw string rather than an enum.
	Arch string `json:"architecture" cyclonedx:"architecture"`
}
