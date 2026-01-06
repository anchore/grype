//nolint:dupl
package processors

import (
	"io"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/unmarshal"
	"github.com/anchore/grype/internal/log"
)

type kevProcessor struct {
	transformer data.KnownExploitedVulnerabilityTransformerV2
}

func NewV2KEVProcessor(transformer data.KnownExploitedVulnerabilityTransformerV2) data.Processor {
	return &kevProcessor{
		transformer: transformer,
	}
}

func (p kevProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.KnownExploitedVulnerabilityEntries(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty KEV entry")
			continue
		}

		transformedEntries, err := p.transformer(entry, state)
		if err != nil {
			return nil, err
		}

		results = append(results, transformedEntries...)
	}

	return results, nil
}

func (p kevProcessor) IsSupported(schemaURL string) bool {
	if !hasSchemaSegment(schemaURL, "known-exploited") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse KEV schema version")
		return false
	}

	return parsedVersion.Major == 1
}
