// Package ignorereasons holds the reason values grype writes on the ignore
// rules created by its own internal suppressions. These become visible to
// consumers via VulnerabilityMatcher.IncludeMatcherSuppressions; the string
// values in output are the interface, not these symbols.
package ignorereasons

const (
	// DistroFixed is the reason recorded when a distro fix record for an
	// owning package suppresses a match on an owned package.
	DistroFixed = "distro-fixed"

	// DistroNAK is the reason recorded when a distro record declaring a
	// package not vulnerable suppresses a match.
	DistroNAK = "distro-nak"
)
