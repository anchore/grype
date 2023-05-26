package griffonerr

import (
	"fmt"
)

// ExpectedErr represents a class of expected errors that griffon may produce.
type ExpectedErr struct {
	Err error
}

// New generates a new ExpectedErr.
func NewExpectedErr(msgFormat string, args ...interface{}) ExpectedErr {
	return ExpectedErr{
		Err: fmt.Errorf(msgFormat, args...),
	}
}

// Error returns a string representing the underlying error condition.
func (e ExpectedErr) Error() string {
	return e.Err.Error()
}
