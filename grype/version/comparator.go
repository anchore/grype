package version

// ComparisonConfig contains configuration for version comparison behavior.
type ComparisonConfig struct {
	// MissingEpochStrategy controls how missing epochs in package versions are handled
	// during vulnerability matching.
	//
	// Valid values:
	//   - "zero": Treat missing epochs as 0 (default, backward compatible)
	//   - "auto": Assume missing epoch matches the constraint's epoch
	MissingEpochStrategy string
}

type Comparator interface {
	// Compare compares this version to another version.
	// This returns -1, 0, or 1 if this version is smaller,
	// equal, or larger than the other version, respectively.
	Compare(*Version) (int, error)
}
