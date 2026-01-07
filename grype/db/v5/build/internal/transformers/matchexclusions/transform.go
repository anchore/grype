package matchexclusions

import (
	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v5"
)

func Transform(matchExclusion unmarshal.MatchExclusion) ([]data.Entry, error) {
	exclusion := grypeDB.VulnerabilityMatchExclusion{
		ID:            matchExclusion.ID,
		Constraints:   nil,
		Justification: matchExclusion.Justification,
	}

	for _, c := range matchExclusion.Constraints {
		constraint := &grypeDB.VulnerabilityMatchExclusionConstraint{
			Vulnerability: grypeDB.VulnerabilityExclusionConstraint{
				Namespace: c.Vulnerability.Namespace,
				FixState:  grypeDB.FixState(c.Vulnerability.FixState),
			},
			Package: grypeDB.PackageExclusionConstraint{
				Name:     c.Package.Name,
				Language: c.Package.Language,
				Type:     c.Package.Type,
				Version:  c.Package.Version,
				Location: c.Package.Location,
			},
		}

		exclusion.Constraints = append(exclusion.Constraints, *constraint)
	}

	entries := []data.Entry{
		{
			DBSchemaVersion: grypeDB.SchemaVersion,
			Data:            exclusion,
		},
	}

	return entries, nil
}
