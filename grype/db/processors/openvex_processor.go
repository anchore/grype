package processors

import (
	"io"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

type openVEXProcessor struct {
	transformer data.OpenVEXTransformerV2
}

func NewV2OpenVEXProcessor(transformer data.OpenVEXTransformerV2) data.Processor {
	return &openVEXProcessor{
		transformer: transformer,
	}
}

func (p openVEXProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.OpenVEXVulnerabilityEntries(reader)
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

func (p openVEXProcessor) IsSupported(schemaURL string) bool {
	if !hasSchemaSegment(schemaURL, "openvex") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse OpenVEX schema version")
		return false
	}

	// OpenVEX at 0.2.X (https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
	return parsedVersion.Major == 0 && parsedVersion.Minor >= 2
}
