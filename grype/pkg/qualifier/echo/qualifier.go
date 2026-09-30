package echo

import (
	internalecho "github.com/anchore/grype/grype/internal/echo"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

// echoQualifier is a NAK qualifier: it only ever appears on
// UnaffectedPackageHandles produced by the echo OSV strategy, and it suppresses
// a candidate match only when the scanned package is itself an Echo build.
// Echo artifacts keep upstream package names, so the build is identified by its
// "+echo.N" version suffix. This is a second guard behind the internal
// echo-prefixed DB key: a non-Echo package fails the qualifier, so the NAK is
// filtered out and the upstream disclosure stands.
type echoQualifier struct{}

// New returns the echo qualifier. There is no per-instance state.
func New() qualifier.Qualifier {
	return echoQualifier{}
}

// Satisfied returns true when the scanned package is an Echo build, detected by
// the "+echo.N" version suffix. A non-Echo package fails the qualifier, which
// causes the NAK to be filtered out of search results.
func (echoQualifier) Satisfied(p pkg.Package) (bool, error) {
	return IsEchoBuild(p.Version), nil
}

// IsEchoBuild reports whether the version string identifies an Echo-patched
// build (carries the "+echo.N" suffix).
func IsEchoBuild(version string) bool {
	return internalecho.IsBuild(version)
}
