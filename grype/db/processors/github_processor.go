//nolint:dupl
package processors

import (
	"io"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/unmarshal"
	"github.com/anchore/grype/internal/log"
)

type githubProcessor struct {
	transformer any
}

func NewGitHubProcessor(transformer data.GitHubTransformer) data.Processor {
	return &githubProcessor{
		transformer: transformer,
	}
}

func NewV2GitHubProcessor(transformer data.GitHubTransformerV2) data.Processor {
	return &githubProcessor{
		transformer: transformer,
	}
}

func (p githubProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.GitHubAdvisoryEntries(reader)
	if err != nil {
		return nil, err
	}

	var handle func(entry unmarshal.GitHubAdvisory) ([]data.Entry, error)
	switch t := p.transformer.(type) {
	case data.GitHubTransformer:
		handle = func(entry unmarshal.GitHubAdvisory) ([]data.Entry, error) {
			return t(entry)
		}
	case data.GitHubTransformerV2:
		handle = func(entry unmarshal.GitHubAdvisory) ([]data.Entry, error) {
			return t(entry, state)
		}
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty GHSA entry")
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

func (p githubProcessor) IsSupported(schemaURL string) bool {
	if !hasSchemaSegment(schemaURL, "github-security-advisory") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse GHSA schema version")
		return false
	}

	return parsedVersion.Major == 1
}
