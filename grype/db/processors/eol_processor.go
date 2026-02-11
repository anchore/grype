//nolint:dupl
package processors

import (
	"io"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

type eolProcessor struct {
	transformer data.EOLTransformerV2
}

func NewV2EOLProcessor(transformer data.EOLTransformerV2) data.Processor {
	return &eolProcessor{
		transformer: transformer,
	}
}

func (p eolProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.EndOfLifeDateReleaseEntries(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty EOL entry")
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

func (p eolProcessor) IsSupported(schemaURL string) bool {
	if !hasSchemaSegment(schemaURL, "eol") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse EOL schema version")
		return false
	}

	return parsedVersion.Major == 1
}
