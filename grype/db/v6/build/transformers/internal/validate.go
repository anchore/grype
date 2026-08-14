package internal

import (
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/version"
)

// FixVersionIsVulnerable reports whether the record's own fix version falls inside its vulnerable
// range. That combination is self-contradictory: the range is what the matcher evaluates, so a
// package installed at exactly the version the record names as the fix is still reported
// vulnerable. It arises when a provider pairs a concrete fix version with a range that was never
// closed above it (e.g. an advisory carrying only an "introduced" event that was later patched
// without the range being updated).
//
// Reported rather than corrected: rewriting a vendor's constraint is the provider's call, and a
// warning makes the bad records visible without changing what any other provider's data means.
//
// A constraint that does not parse, or a fix version that cannot be compared in the record's
// format, returns false — unparseable data is ValidateAffectedVersion's concern, not this check's.
func FixVersionIsVulnerable(v db.Version, fixVersion string) bool {
	if fixVersion == "" || v.Constraint == "" {
		return false
	}

	versionFormat := version.ParseFormat(v.Type)
	c, err := version.GetConstraint(v.Constraint, versionFormat)
	if err != nil {
		return false
	}

	fix := version.New(fixVersion, versionFormat)
	if err := fix.Validate(); err != nil {
		return false
	}

	satisfied, err := c.Satisfied(fix)
	if err != nil {
		return false
	}

	return satisfied
}

func ValidateAffectedVersion(v db.Version) error {
	versionFormat := version.ParseFormat(v.Type)
	c, err := version.GetConstraint(v.Constraint, versionFormat)
	if err != nil {
		return err
	}

	// ensure we can use this version format in a comparison
	ver := version.New("1.0.0", versionFormat)
	if err := ver.Validate(); err != nil {
		// don't have a good example to use here
		// TODO: we should consider finding a better way to do this without having to create a valid version for comparison
		return nil
	}

	_, err = c.Satisfied(ver)

	return err
}
