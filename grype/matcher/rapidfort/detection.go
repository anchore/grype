package rapidfort

import "github.com/anchore/grype/grype/pkg"

// IsRapidFortImage reads the pre-populated flag on pkg.Context.
// Detection itself happens in the package providers; see pkg.RapidFortMarkerPath.
func IsRapidFortImage(ctx pkg.Context) bool {
	return ctx.IsRapidFortImage
}
