package version

// MissingEpochStrategy defines how missing epochs in package versions are handled
// during vulnerability matching.
type MissingEpochStrategy string

const (
	// MissingEpochStrategyZero treats missing epochs as 0 (default, backward compatible)
	MissingEpochStrategyZero MissingEpochStrategy = "zero"
	// MissingEpochStrategyAuto assumes missing epoch matches the constraint's epoch
	MissingEpochStrategyAuto MissingEpochStrategy = "auto"
)

// ComparisonConfig contains configuration for version comparison behavior.
type ComparisonConfig struct {
	// MissingEpochStrategy controls how missing epochs in package versions are handled
	// during vulnerability matching.
	//
	// Valid values:
	//   - MissingEpochStrategyZero ("zero"): Treat missing epochs as 0 (default, backward compatible)
	//   - MissingEpochStrategyAuto ("auto"): Assume missing epoch matches the constraint's epoch
	MissingEpochStrategy MissingEpochStrategy
}

type Comparator interface {
	// Compare compares this version to another version.
	// This returns -1, 0, or 1 if this version is smaller,
	// equal, or larger than the other version, respectively.
	Compare(*Version) (int, error)
}
