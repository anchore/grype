package processors // nolint:dupl

import (
	"io"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/unmarshal"
	"github.com/anchore/grype/internal/log"
)

type annotatedOpenVEXProcessor struct {
	transformer data.AnnotatedOpenVEXTransformerV2
}

func NewV2AnnotatedOpenVEXProcessor(transformer data.AnnotatedOpenVEXTransformerV2) data.Processor {
	return &annotatedOpenVEXProcessor{
		transformer: transformer,
	}
}

func (p annotatedOpenVEXProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.AnnotatedOpenVEXVulnerabilityEntries(reader)
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

func (p annotatedOpenVEXProcessor) IsSupported(schemaURL string) bool {
	if !hasSchemaSegment(schemaURL, "annotated-openvex") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse annotated OpenVEX schema version")
		return false
	}

	return parsedVersion.Major == 1
}
