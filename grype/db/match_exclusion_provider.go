package db

import (
	"fmt"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"

	grypeDB "github.com/anchore/grype/grype/db/v4"
)

var _ match.ExclusionProvider = (*MatchExclusionProvider)(nil)

type MatchExclusionProvider struct {
	reader grypeDB.VulnerabilityMatchExclusionStoreReader
}

func NewMatchExclusionProvider(reader grypeDB.VulnerabilityMatchExclusionStoreReader) *MatchExclusionProvider {
	return &MatchExclusionProvider{
		reader: reader,
	}
}

func (pr *MatchExclusionProvider) GetRules(vulnerabilityId string) ([]match.IgnoreRule, error) {
	matchExclusions, err := pr.reader.GetVulnerabilityMatchExclusion(vulnerabilityId)
	if err != nil {
		return nil, fmt.Errorf("match exclusion provider failed to fetch records for vulnerability id='%s': %w", vulnerabilityId, err)
	}

	var ignoreRules []match.IgnoreRule

	for _, e := range matchExclusions {
		if len(e.Constraints) == 0 {
			ignoreRules = append(ignoreRules, match.IgnoreRule{
				Vulnerability: e.ID,
			})
		}

		for _, c := range e.Constraints {
			
		}
	}

	return vulnerability.NewMetadata(metadata)
}
