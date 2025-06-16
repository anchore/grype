package version

import (
	"errors"
	"fmt"
)

var ErrNoVersionProvided = errors.New("no version provided for comparison")

// UnsupportedComparisonError represents an error when a format doesn't match the expected format
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
	return fmt.Sprintf("(%s) unsupported version comparison: value=%q format=%q", e.Left, e.Right.Raw, e.Right.Format)
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

func newNotComparableError(left Format, other *Version) error {
	if other == nil {
		return fmt.Errorf("cannot compare %q formatted version with empty version", left)
	}
	if other.comparator == nil {
		return fmt.Errorf("cannot compare %q formatted version with empty version object", left)
	}
	if left != other.Format {
		return newUnsupportedFormatError(left, other)
	}
	return fmt.Errorf("cannot compare %q objects", left)
}
