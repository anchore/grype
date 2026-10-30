package lightwell

import (
	"github.com/anchore/grype/grype/internal/lightwell"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

// lightwellBaseVersion is a NAK qualifier: it only ever appears on
// UnaffectedPackageHandles produced by the lightwell OSV strategy. Each
// Lightwell advisory covers a single upstream base-version line, so the
// qualifier is satisfied only by a Lightwell build of that line. This keeps
// an advisory from suppressing findings on ordinary upstream builds, and on
// Lightwell builds of other lines (e.g. the 5.0.3 line's advisory must not
// clear a 6.2.2.rhlw-* build, even though it orders above the 5.0.3 fix).
type lightwellBaseVersion struct {
	baseVersion string
}

// New returns a qualifier that is satisfied by Lightwell builds remediated
// from the given upstream base version.
func New(baseVersion string) qualifier.Qualifier {
	return lightwellBaseVersion{baseVersion: baseVersion}
}

// Satisfied returns true when the scanned package is a Lightwell build whose
// upstream base version is the one the advisory covers.
func (q lightwellBaseVersion) Satisfied(p pkg.Package) (bool, error) {
	base, ok := lightwell.BaseVersion(p.Version)
	return ok && base == q.baseVersion, nil
}
