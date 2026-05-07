//nolint:dupl
package processors

import (
	"io"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

type epssProcessor struct {
	transformer data.EPSSTransformerV2
}

func NewV2EPSSProcessor(transformer data.EPSSTransformerV2) data.Processor {
	return &epssProcessor{
		transformer: transformer,
	}
}

func (p epssProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.EPSSEntries(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty EPSS entry")
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

func (p epssProcessor) IsSupported(schemaURL string) bool {
	if !hasSchemaSegment(schemaURL, "epss") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse EPSS schema version")
		return false
	}

	return parsedVersion.Major == 1
}
