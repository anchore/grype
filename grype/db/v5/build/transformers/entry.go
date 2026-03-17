package transformers

import (
	"github.com/anchore/grype/grype/db/data"
	db "github.com/anchore/grype/grype/db/v5"
)

func NewEntries(vs []db.Vulnerability, metadata db.VulnerabilityMetadata) []data.Entry {
	entries := []data.Entry{
		{
			DBSchemaVersion: db.SchemaVersion,
			Data:            metadata,
		},
	}
	for _, vuln := range vs {
		entries = append(entries, data.Entry{
			DBSchemaVersion: db.SchemaVersion,
			Data:            vuln,
		})
	}
	return entries
}
