// Package lightwell recognizes Red Hat Lightwell remediated builds by their
// version suffix. The DB builder (OSV lightwell strategy) and the result-side
// qualifier in grype/pkg/qualifier/lightwell both derive a build's upstream
// base version from it, so the two sides agree on which line a build is on.
package lightwell

import "regexp"

// suffix matches the remediation suffix Lightwell appends to the upstream
// version it backported a fix into. All of these shapes are published:
//
//   - Maven, dot separated:  6.0.3.rhlw-00001
//   - Maven, dash separated: 4.1.100.Final-rhlw-00001
//   - PyPI local version:    3.0.1+rhlw.1
var suffix = regexp.MustCompile(`(?i)[.+-]rhlw[.-]\d+$`)

// BaseVersion returns the upstream version a Lightwell build was remediated
// from (e.g. "6.0.3" for "6.0.3.rhlw-00001"), and false when the version
// carries no Lightwell suffix.
func BaseVersion(version string) (string, bool) {
	loc := suffix.FindStringIndex(version)
	if loc == nil || loc[0] == 0 {
		return "", false
	}
	return version[:loc[0]], true
}
