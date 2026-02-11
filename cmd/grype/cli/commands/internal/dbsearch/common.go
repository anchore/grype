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

func filterByFixedStateForPackages(packages []affectedPackageWithDecorations, fixedStates []string) []affectedPackageWithDecorations {
	if len(fixedStates) == 0 {
		return packages
	}

	stateSet := make(map[string]bool)
	for _, state := range fixedStates {
		stateSet[state] = true
	}

	var filtered []affectedPackageWithDecorations
	for _, pkg := range packages {
		if pkg.BlobValue == nil {
			continue
		}

		fixState := getFixStateFromPackageBlob(pkg.BlobValue)
		if stateSet[fixState] {
			filtered = append(filtered, pkg)
		}
	}

	return filtered
}

func filterByFixedStateForCPEs(cpes []affectedCPEWithDecorations, fixedStates []string) []affectedCPEWithDecorations {
	if len(fixedStates) == 0 {
		return cpes
	}

	stateSet := make(map[string]bool)
	for _, state := range fixedStates {
		stateSet[state] = true
	}

	var filtered []affectedCPEWithDecorations
	for _, cpe := range cpes {
		if cpe.BlobValue == nil {
			continue
		}

		fixState := getFixStateFromPackageBlob(cpe.BlobValue)
		if stateSet[fixState] {
			filtered = append(filtered, cpe)
		}
	}

	return filtered
}
