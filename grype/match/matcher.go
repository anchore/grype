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

// fatalError can be returned from a Matcher to indicate the matching process should stop.
// When fatalError(s) are encountered by the top-level matching process, these will be returned as errors to the caller.
type fatalError struct {
	matcher MatcherType
	inner   error
}

// NewFatalError creates a new FatalError wrapping the given error
func NewFatalError(matcher MatcherType, e error) error {
	return fatalError{matcher: matcher, inner: e}
}

// Error implements the error interface for FatalError.
func (f fatalError) Error() string {
	return fmt.Sprintf("%s encountered a fatal error: %v", f.matcher, f.inner)
}

// IsFatalError returns true if err includes a FatalError
func IsFatalError(err error) bool {
	var fe fatalError
	return err != nil && errors.As(err, &fe)
}
