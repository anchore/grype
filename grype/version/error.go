package version

import (
	"errors"
	"fmt"
)

// ErrUnsupportedVersion is returned when a version string cannot be parsed because the value is known
// to cause issues or is otherwise problematic (e.g. golang "devel" version).
var ErrUnsupportedVersion = fmt.Errorf("unsupported version value")

// ErrNoVersionProvided is returned when a version is attempted to be compared, but no other version is provided to compare against.
var ErrNoVersionProvided = errors.New("no version provided for comparison")

// UnsupportedComparisonError represents an error when a Fmt doesn't match the expected Fmt
type UnsupportedComparisonError struct {
	Left  Format
	Right *Version
}

// newUnsupportedFormatError creates a new UnsupportedComparisonError
func newUnsupportedFormatError(left Format, right *Version) *UnsupportedComparisonError {
	return &UnsupportedComparisonError{
		Left:  left,
		Right: right,
	}
}

func (e *UnsupportedComparisonError) Error() string {
	return fmt.Sprintf("(%s) unsupported version comparison: value=%q Fmt=%q", e.Left, e.Right.Raw, e.Right.Format)
}

func (e *UnsupportedComparisonError) Is(target error) bool {
	var t *UnsupportedComparisonError
	ok := errors.As(target, &t)
	if !ok {
		return false
	}
	return (t.Left == UnknownFormat || t.Left == e.Left) &&
		(t.Right.Format == UnknownFormat || t.Right == e.Right)
}

func invalidFormatError(format Format, raw string, err error) error {
	return fmt.Errorf("invalid %s version from '%s': %w", format.String(), raw, err)
}

// NonFatalConstraintError should be used any time an unexpected but recoverable condition is encountered while
// checking version constraint satisfaction. The error should get returned by any implementer of the Constraint
// interface. If returned by the Satisfied method on the Constraint interface, this error will be caught and
// logged as a warning in the FindMatchesByPackageDistro function in grype/matcher/common/distro_matchers.go
type NonFatalConstraintError struct {
	constraint Constraint
	version    *Version
	message    string
}

func (e NonFatalConstraintError) Error() string {
	return fmt.Sprintf("matching Raw constraint %s against version %s caused a non-fatal error: %s", e.constraint, e.version, e.message)
}
