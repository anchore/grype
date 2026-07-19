package rapidfort

import "github.com/anchore/grype/grype/pkg"

// IsRapidFortImage reports whether the scan target has been identified as a
// RapidFort-curated container image.
//
// Detection is performed at package-provider time (see pkg.RapidFortMarkerPath
// and the pkg.Context.IsRapidFortImage field): the presence of the marker file
// /usr/share/rapidfort/curated.json in the image or SBOM catalog is the sole
// authoritative signal. This function is a thin accessor that lets the
// matcher-selection layer (matcher.ApplySelectionPolicy) query the already-
// populated flag without knowing how detection was performed.
//
// A zero-value pkg.Context (e.g. from PURL/CPE inputs or the deprecated
// FindVulnerabilitiesForPackage entrypoint) yields false, which is the safe
// default: the RapidFort matcher stays inactive and standard OS matchers are
// used.
func IsRapidFortImage(ctx pkg.Context) bool {
	return ctx.IsRapidFortImage
}
