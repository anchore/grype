//nolint:dupl
package processors

import (
	"io"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/unmarshal"
	"github.com/anchore/grype/internal/log"
)

type matchExclusionProcessor struct {
	transformer data.MatchExclusionTransformer
}

func NewMatchExclusionProcessor(transformer data.MatchExclusionTransformer) data.Processor {
	return &matchExclusionProcessor{
		transformer: transformer,
	}
}

func (p matchExclusionProcessor) Process(reader io.Reader, _ provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.MatchExclusions(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty match-exclusion entry")
			continue
		}

		transformedEntries, err := p.transformer(entry)
		if err != nil {
			return nil, err
		}

		results = append(results, transformedEntries...)
	}

	return results, nil
}

func (p matchExclusionProcessor) IsSupported(schemaURL string) bool {
	if !hasSchemaSegment(schemaURL, "match-exclusion") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse match-exclusion schema version")
		return false
	}

	return parsedVersion.Major == 1
}
