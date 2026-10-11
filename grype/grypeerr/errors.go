package grypeerr

var (
	// ErrAboveSeverityThreshold indicates when a vulnerability severity is discovered that is equal
	// or above the given --fail-on severity value.
	ErrAboveSeverityThreshold = NewExpectedErr("discovered vulnerabilities at or above the severity threshold")

	// ErrAboveRiskThreshold indicates when a vulnerability risk score is discovered that is equal
	// or above the given --fail-on risk value.
	ErrAboveRiskThreshold = NewExpectedErr("discovered vulnerabilities at or above the risk threshold")

	// ErrDBUpgradeAvailable indicates that a DB upgrade is available.
	ErrDBUpgradeAvailable = NewExpectedErr("db upgrade available")
)
