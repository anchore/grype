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

// MissingApkReleaseStrategy defines how a package version without an apk release suffix ("-rN")
// is compared against a constraint version that has one.
//
// Every real apk package carries a release suffix (abuild's pkgrel, melange's epoch), so a bare
// version like "3.6.3" only appears when an SBOM or purl author dropped it. apk-tools sorts a bare
// version below "-r0", which makes "3.6.3" vulnerable to a "< 3.6.3-r0" fix.
type MissingApkReleaseStrategy string

const (
	// MissingApkReleaseStrategyZero treats a missing release suffix as "-r0": the first build of
	// that upstream version
	MissingApkReleaseStrategyZero MissingApkReleaseStrategy = "zero"
	// MissingApkReleaseStrategyStrict compares as apk-tools does: a bare version sorts below "-r0"
	MissingApkReleaseStrategyStrict MissingApkReleaseStrategy = "strict"
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

	// MissingApkReleaseStrategy controls how apk package versions without a release suffix
	// ("-rN") are handled during vulnerability matching. Empty preserves apk-tools ordering.
	//
	// Valid values:
	//   - MissingApkReleaseStrategyZero ("zero"): Treat a missing release as "-r0"
	//   - MissingApkReleaseStrategyStrict ("strict"): Compare as apk-tools does
	MissingApkReleaseStrategy MissingApkReleaseStrategy
}

// hasConfig reports whether any strategy is set, i.e. whether config-aware comparison applies.
func (c ComparisonConfig) hasConfig() bool {
	return c.MissingEpochStrategy != "" || c.MissingApkReleaseStrategy != ""
}

type Comparator interface {
	// Compare compares this version to another version.
	// This returns -1, 0, or 1 if this version is smaller,
	// equal, or larger than the other version, respectively.
	Compare(*Version) (int, error)
}
