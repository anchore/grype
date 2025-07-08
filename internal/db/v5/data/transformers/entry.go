package transformers

import (
	"github.com/anchore/grype/grype/db/data"
	v5 "github.com/anchore/grype/internal/db/v5"
)

func NewEntries(vs []v5.Vulnerability, metadata v5.VulnerabilityMetadata) []data.Entry {
	entries := []data.Entry{
		{
			DBSchemaVersion: v5.SchemaVersion,
			Data:            metadata,
		},
	}
	for _, vuln := range vs {
		entries = append(entries, data.Entry{
			DBSchemaVersion: v5.SchemaVersion,
			Data:            vuln,
		})
	}
	return entries
}
