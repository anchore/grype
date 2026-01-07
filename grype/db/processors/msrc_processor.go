//nolint:dupl
package processors

import (
	"io"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

// msrcProcessor defines the regular expression needed to signal what is supported
type msrcProcessor struct {
	transformer any
}

// NewMSRCProcessor creates a new instance of msrcProcessor particular to MSRC
func NewMSRCProcessor(transformer data.MSRCTransformer) data.Processor {
	return &msrcProcessor{
		transformer: transformer,
	}
}

func NewV2MSRCProcessor(transformer data.MSRCTransformerV2) data.Processor {
	return &msrcProcessor{
		transformer: transformer,
	}
}

func (p msrcProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.MSRCVulnerabilityEntries(reader)
	if err != nil {
		return nil, err
	}

	var handle func(entry unmarshal.MSRCVulnerability) ([]data.Entry, error)
	switch t := p.transformer.(type) {
	case data.MSRCTransformer:
		handle = func(entry unmarshal.MSRCVulnerability) ([]data.Entry, error) {
			return t(entry)
		}
	case data.MSRCTransformerV2:
		handle = func(entry unmarshal.MSRCVulnerability) ([]data.Entry, error) {
			return t(entry, state)
		}
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty MSRC entry")
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

func (p msrcProcessor) IsSupported(schemaURL string) bool {
	if !hasSchemaSegment(schemaURL, "msrc") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse MSRC schema version")
		return false
	}

	return parsedVersion.Major == 1
}
