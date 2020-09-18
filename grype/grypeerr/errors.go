package grypeerr

var (
	// ErrAboveAllowableSeverity indicates when a vulnerability severity is discovered that is above the given --fail-on severity value
	ErrAboveAllowableSeverity = NewExpectedErr("discovered vulnerabilities at or above the maximum allowable severity")
)
