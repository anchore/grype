package db

import (
	"fmt"

	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
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

func buildIgnoreRulesFromMatchExclusion(e grypeDB.VulnerabilityMatchExclusion) []match.IgnoreRule {
	var ignoreRules []match.IgnoreRule

	if len(e.Constraints) == 0 {
		ignoreRules = append(ignoreRules, match.IgnoreRule{Vulnerability: e.ID})
		return ignoreRules
	}

	for _, c := range e.Constraints {
		ignoreRules = append(ignoreRules, match.IgnoreRule{
			Vulnerability: e.ID,
			Namespace:     c.Vulnerability.Namespace,
			FixState:      string(c.Vulnerability.FixState),
			Package: match.IgnoreRulePackage{
				Name:     c.Package.Name,
				Language: c.Package.Language,
				Type:     c.Package.Type,
				Location: c.Package.Location,
				Version:  c.Package.Version,
			},
		})
	}

	return ignoreRules
}

func (pr *MatchExclusionProvider) GetRules(vulnerabilityID string) ([]match.IgnoreRule, error) {
	matchExclusions, err := pr.reader.GetVulnerabilityMatchExclusion(vulnerabilityID)
	if err != nil {
		return nil, fmt.Errorf("match exclusion provider failed to fetch records for vulnerability id='%s': %w", vulnerabilityID, err)
	}

	var ignoreRules []match.IgnoreRule

	for _, e := range matchExclusions {
		rules := buildIgnoreRulesFromMatchExclusion(e)
		ignoreRules = append(ignoreRules, rules...)
	}

	return ignoreRules, nil
}
