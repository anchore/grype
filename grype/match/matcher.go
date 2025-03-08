package match

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// Matcher is the interface to implement to provide top-level package-to-match
type Matcher interface {
	PackageTypes() []syftPkg.Type

	Type() MatcherType

	// Match is called for every package found, returning any matches and an optional Ignorer which will be applied
	// after all matches are found
	Match(vp vulnerability.Provider, p pkg.Package) ([]Match, []IgnoredMatch, error)
}

// FatalError wraps an error that occurs during matching that is worth of
// bubbling up to the user and yielding an unsuccessful scan. FatalError can be
// checked for using errors.As().
type FatalError struct {
	inner error
}

// NewFatalError creates a new FatalError wrapping the given error.
func NewFatalError(e error) FatalError {
	return FatalError{inner: e}
}

// Error implements the error interface for FatalError.
func (f FatalError) Error() string {
	return fmt.Sprintf("vulnerability matching cannot continue: %v", f.inner)
}

// IsFatal returns true if err's tree includes a FatalErr.
func IsFatal(err error) bool {
	var fe FatalError
	return err != nil && errors.As(err, &fe)
}
