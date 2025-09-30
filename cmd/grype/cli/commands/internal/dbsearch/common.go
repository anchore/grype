package dbsearch

import v6 "github.com/anchore/grype/grype/db/v6"

const (
	fixStateFixed    = "fixed"
	fixStateNotFixed = "not-fixed"
	fixStateWontFix  = "wont-fix"
	fixStateUnknown  = "unknown"
)

// getFixStateFromPackageBlob determines the overall fix state for a package blob.
// When multiple ranges exist with different fix states, precedence is applied:
// fixed > wont-fix > not-fixed > unknown
// This ensures that if ANY range has a fix available, the package is considered fixable.
func getFixStateFromPackageBlob(blob *v6.PackageBlob) string {
	if blob == nil {
		return fixStateUnknown
	}

	hasFixed := false
	hasNotFixed := false
	hasWontFix := false

	for _, r := range blob.Ranges {
		if r.Fix == nil {
			continue
		}
		switch r.Fix.State {
		case v6.FixedStatus:
			hasFixed = true
		case v6.WontFixStatus:
			hasWontFix = true
		case v6.NotFixedStatus:
			hasNotFixed = true
		}
	}

	if hasFixed {
		return fixStateFixed
	}
	if hasWontFix {
		return fixStateWontFix
	}
	if hasNotFixed {
		return fixStateNotFixed
	}

	return fixStateUnknown
}
