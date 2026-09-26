package pkg

// RustMetadata holds the Cargo.lock evidence used for Rust vulnerability matching.
// Cargo omits the source field for workspace and path dependencies, while registry
// and git dependencies include a non-empty source.
type RustMetadata struct {
	RustCargoLockSource string `json:"rustCargoLockSource"`
}
