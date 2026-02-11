//nolint:dupl
package processors

import (
	"io"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

type osProcessor struct {
	transformer any
}

func NewOSProcessor(transformer data.OSTransformer) data.Processor {
	return &osProcessor{
		transformer: transformer,
	}
}

func NewV2OSProcessor(transformer data.OSTransformerV2) data.Processor {
	return &osProcessor{
		transformer: transformer,
	}
}

func (p osProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.OSVulnerabilityEntries(reader)
	if err != nil {
		return nil, err
	}

	var handle func(entry unmarshal.OSVulnerability) ([]data.Entry, error)
	switch t := p.transformer.(type) {
	case data.OSTransformer:
		handle = func(entry unmarshal.OSVulnerability) ([]data.Entry, error) {
			return t(entry)
		}
	case data.OSTransformerV2:
		handle = func(entry unmarshal.OSVulnerability) ([]data.Entry, error) {
			return t(entry, state)
		}
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty OS entry")
			continue
		}

		transformedEntries, err := handle(entry)
		if err != nil {
			return nil, err
		}

		results = append(results, transformedEntries...)
	}

	return results, nil
}

func (p osProcessor) IsSupported(schemaURL string) bool {
	if !hasSchemaSegment(schemaURL, "os") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse OS schema version")
		return false
	}

	return parsedVersion.Major == 1
}
