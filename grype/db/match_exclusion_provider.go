package db

import (
	"fmt"
	grypeDB "github.com/anchore/grype/grype/db/v4"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/log"
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

func buildIgnoreRulesFromMatchExclusion(e grypeDB.VulnerabilityMatchExclusion) ([]match.IgnoreRule, error) {
	var ignoreRules []match.IgnoreRule

	constraints := e.Constraints

	if len(e.Constraints) == 0 {
		constraints = []grypeDB.VulnerabilityMatchExclusionConstraint{{}}
	}

	for _, c := range constraints {
		namespaces := c.Namespaces

		if len(namespaces) == 0 {
			namespaces = []string{""}
		}

		fixStates := c.FixStates

		if len(fixStates) == 0 {
			fixStates = []grypeDB.FixState{""}
		}

		ecosystemConstraints := c.EcosystemConstraints

		if len(ecosystemConstraints) == 0 {
			ecosystemConstraints = []grypeDB.VulnerabilityMatchExclusionEcosystemConstraint{{}}
		}

		for _, ec := range ecosystemConstraints {
			packageConstraints := ec.PackageConstraints

			if len(packageConstraints) == 0 {
				packageConstraints = []grypeDB.VulnerabilityMatchExclusionPackageConstraint{{}}
			}

			for _, pc := range packageConstraints {
				versions := pc.Versions

				if len(versions) == 0 {
					versions = []string{""}
				}

				locations := pc.Locations

				if len(locations) == 0 {
					locations = []string{""}
				}

				for _, n := range namespaces {
					for _, f := range fixStates {
						for _, v := range versions {
							for _, l := range locations {
								ignoreRules = append(ignoreRules, match.IgnoreRule{
									Vulnerability: e.ID,
									Namespace:     n,
									FixState:      string(f),
									Package: match.IgnoreRulePackage{
										Name:     pc.PackageName,
										Language: ec.Language,
										Type:     ec.PackageType,
										Location: l,
										Version:  v,
									},
								})
							}
						}
					}
				}
			}
		}
	}

	return ignoreRules, nil
}

func (pr *MatchExclusionProvider) GetRules(vulnerabilityId string) ([]match.IgnoreRule, error) {
	matchExclusions, err := pr.reader.GetVulnerabilityMatchExclusion(vulnerabilityId)
	if err != nil {
		return nil, fmt.Errorf("match exclusion provider failed to fetch records for vulnerability id='%s': %w", vulnerabilityId, err)
	}

	var ignoreRules []match.IgnoreRule

	for _, e := range matchExclusions {
		rules, err := buildIgnoreRulesFromMatchExclusion(e)

		if err != nil {
			log.Warnf("failed to build ignore rules from a match exclusion record for vuln id=%s", e.ID)
		}

		ignoreRules = append(ignoreRules, rules...)
	}

	return ignoreRules, nil
}
