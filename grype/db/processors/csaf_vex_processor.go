package processors // nolint:dupl

import (
	"io"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

type csafVEXProcessor struct {
	transformer data.CSAFVEXTransformerV2
}

func NewV2CSAFVEXProcessor(transformer data.CSAFVEXTransformerV2) data.Processor {
	return &csafVEXProcessor{
		transformer: transformer,
	}
}

func (p csafVEXProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.CSAFVEXAdvisoryEntries(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		transformedEntries, err := p.transformer(entry, state)
		if err != nil {
			return nil, err
		}

		results = append(results, transformedEntries...)
	}

	return results, nil
}

func (p csafVEXProcessor) IsSupported(schemaURL string) bool {
	if !hasSchemaSegment(schemaURL, "csaf-vex") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse CSAF VEX schema version")
		return false
	}

	return parsedVersion.Major == 2
}
