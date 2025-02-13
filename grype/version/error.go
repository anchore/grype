package version

import (
	"errors"
	"fmt"
)

// UnsupportedFormatError represents an error when a format doesn't match the expected format
type UnsupportedFormatError struct {
	Left  Format
	Right Format
}

// NewUnsupportedFormatError creates a new UnsupportedFormatError
func NewUnsupportedFormatError(left, right Format) *UnsupportedFormatError {
	return &UnsupportedFormatError{
		Left:  left,
		Right: right,
	}
}

func (e *UnsupportedFormatError) Error() string {
	return fmt.Sprintf("(%s) unsupported format: %s", e.Left, e.Right)
}

func (e *UnsupportedFormatError) Is(target error) bool {
	var t *UnsupportedFormatError
	ok := errors.As(target, &t)
	if !ok {
		return false
	}
	return (t.Left == UnknownFormat || t.Left == e.Left) &&
		(t.Right == UnknownFormat || t.Right == e.Right)
}
