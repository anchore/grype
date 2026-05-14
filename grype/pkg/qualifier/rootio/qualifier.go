package rootio

import (
	"github.com/anchore/grype/grype/internal/rootio"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

// rootIO is a NAK qualifier: it only ever appears on UnaffectedPackageHandles
// produced by the rootio OSV strategy, and it suppresses any candidate match
// against a scanned package that isn't itself a rootio build. Presence of
// the qualifier in the slice *is* the requirement — there's no per-instance
// configuration.
type rootIO struct{}

// New returns the rootio qualifier. There is no per-instance state.
func New() qualifier.Qualifier {
	return rootIO{}
}

// Satisfied returns true when the scanned package is a rootio build. A
// non-rootio scanned package fails the qualifier, which causes the NAK to
// be filtered out of search results.
func (rootIO) Satisfied(p pkg.Package) (bool, error) {
	return rootio.IsPackage(p), nil
}
