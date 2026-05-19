package matchexclusions

import (
	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	db "github.com/anchore/grype/grype/db/v5"
)

func Transform(matchExclusion unmarshal.MatchExclusion) ([]data.Entry, error) {
	exclusion := db.VulnerabilityMatchExclusion{
		ID:            matchExclusion.ID,
		Constraints:   nil,
		Justification: matchExclusion.Justification,
	}

	for _, c := range matchExclusion.Constraints {
		constraint := &db.VulnerabilityMatchExclusionConstraint{
			Vulnerability: db.VulnerabilityExclusionConstraint{
				Namespace: c.Vulnerability.Namespace,
				FixState:  db.FixState(c.Vulnerability.FixState),
			},
			Package: db.PackageExclusionConstraint{
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
			DBSchemaVersion: db.SchemaVersion,
			Data:            exclusion,
		},
	}

	return entries, nil
}
