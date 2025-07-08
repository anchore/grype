package matchexclusions

import (
	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/internal/db/data/unmarshal"
	v5 "github.com/anchore/grype/internal/db/v5"
)

func Transform(matchExclusion unmarshal.MatchExclusion) ([]data.Entry, error) {
	exclusion := v5.VulnerabilityMatchExclusion{
		ID:            matchExclusion.ID,
		Constraints:   nil,
		Justification: matchExclusion.Justification,
	}

	for _, c := range matchExclusion.Constraints {
		constraint := &v5.VulnerabilityMatchExclusionConstraint{
			Vulnerability: v5.VulnerabilityExclusionConstraint{
				Namespace: c.Vulnerability.Namespace,
				FixState:  v5.FixState(c.Vulnerability.FixState),
			},
			Package: v5.PackageExclusionConstraint{
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
			DBSchemaVersion: v5.SchemaVersion,
			Data:            exclusion,
		},
	}

	return entries, nil
}
