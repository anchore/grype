package grypeerr

var (
	// ErrAboveSeverityThreshold indicates when a vulnerability severity is discovered that is equal
	// or above the given --fail-on severity value.
	ErrAboveSeverityThreshold = NewExpectedErr("discovered vulnerabilities at or above the severity threshold")

	// ErrMissingVexStatement indicates when --fail-on no-vex-statement is given and a vulnerability is discovered
	// that no provided VEX document makes a statement about.
	ErrMissingVexStatement = NewExpectedErr("discovered vulnerabilities without a VEX statement")

	// ErrDBUpgradeAvailable indicates that a DB upgrade is available.
	ErrDBUpgradeAvailable = NewExpectedErr("db upgrade available")
)
