package models

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// Match is a single item for the JSON array reported
type Match struct {
	Vulnerability          Vulnerability           `json:"vulnerability"`
	RelatedVulnerabilities []VulnerabilityMetadata `json:"relatedVulnerabilities"`
	MatchDetails           MatchDetails            `json:"matchDetails"`
	Artifact               Package                 `json:"artifact"`
}

// MatchDetails contains all data that indicates how the result match was found
type MatchDetails struct {
	Matcher    string                 `json:"matcher"`
	SearchedBy map[string]interface{} `json:"searchedBy"`
	MatchedOn  map[string]interface{} `json:"matchedOn"`
}

func newMatch(m match.Match, p pkg.Package, metadataProvider vulnerability.MetadataProvider) (*Match, error) {
	relatedVulnerabilities := make([]VulnerabilityMetadata, 0)
	for _, r := range m.Vulnerability.RelatedVulnerabilities {
		relatedMetadata, err := metadataProvider.GetMetadata(r.ID, r.Namespace)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch related vuln=%q metadata: %+v", r, err)
		}
		if relatedMetadata != nil {
			relatedVulnerabilities = append(relatedVulnerabilities, NewVulnerabilityMetadata(r.ID, r.Namespace, relatedMetadata))
		}
	}

	metadata, err := metadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.Namespace)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch vuln=%q metadata: %+v", m.Vulnerability.ID, err)
	}

	return &Match{
		Vulnerability:          NewVulnerability(m.Vulnerability, metadata),
		Artifact:               newPackage(p),
		RelatedVulnerabilities: relatedVulnerabilities,
		MatchDetails: MatchDetails{
			Matcher:    m.Matcher.String(),
			SearchedBy: m.SearchKey,
			MatchedOn:  m.SearchMatches,
		},
	}, nil
}
