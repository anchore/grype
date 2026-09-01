package internal

import (
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/version"
)

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
