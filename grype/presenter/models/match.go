package models

import (
	"fmt"
	"sort"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// Match is a single item for the JSON array reported
type Match struct {
	Vulnerability          Vulnerability           `json:"vulnerability"`
	RelatedVulnerabilities []VulnerabilityMetadata `json:"relatedVulnerabilities"`
	MatchDetails           []MatchDetails          `json:"matchDetails"`
	Artifact               Package                 `json:"artifact"`
}

// MatchDetails contains all data that indicates how the result match was found
type MatchDetails struct {
	Type       string      `json:"type"`
	Matcher    string      `json:"matcher"`
	SearchedBy interface{} `json:"searchedBy"` // The specific attributes that were used to search (other than package name and version) --this indicates "how" the match was made.
	Found      interface{} `json:"found"`      // The specific attributes on the vulnerability object that were matched with --this indicates "what" was matched on / within.
}

func newMatch(m match.Match, p pkg.Package, metadataProvider vulnerability.MetadataProvider) (*Match, error) {
	relatedVulnerabilities := make([]VulnerabilityMetadata, 0)
	for _, r := range m.Vulnerability.RelatedVulnerabilities {
		relatedMetadata, err := metadataProvider.VulnerabilityMetadata(r)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch related vuln=%q metadata: %+v", r, err)
		}
		if relatedMetadata != nil {
			relatedVulnerabilities = append(relatedVulnerabilities, NewVulnerabilityMetadata(r.ID, r.Namespace, relatedMetadata))
		}
	}

	metadata, err := metadataProvider.VulnerabilityMetadata(m.Vulnerability.Reference)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch vuln=%q metadata: %+v", m.Vulnerability.ID, err)
	}

	details := make([]MatchDetails, len(m.Details))
	for idx, d := range m.Details {
		details[idx] = MatchDetails{
			Type:       string(d.Type),
			Matcher:    string(d.Matcher),
			SearchedBy: d.SearchedBy,
			Found:      d.Found,
		}
	}

	return &Match{
		Vulnerability:          NewVulnerability(m.Vulnerability, metadata),
		Artifact:               newPackage(p),
		RelatedVulnerabilities: relatedVulnerabilities,
		MatchDetails:           details,
	}, nil
}

var _ sort.Interface = (*MatchSort)(nil)

type MatchSort []Match

// Len is the number of elements in the collection.
func (m MatchSort) Len() int {
	return len(m)
}

// Less reports whether the element with index i should sort before the element with index j.
// sort should consistent across presenters: name, version, type, severity, vulnerability
func (m MatchSort) Less(i, j int) bool {
	matchI := m[i]
	matchJ := m[j]
	if matchI.Artifact.Name == matchJ.Artifact.Name {
		if matchI.Artifact.Version == matchJ.Artifact.Version {
			if matchI.Artifact.Type == matchJ.Artifact.Type {
				if SeverityScore(matchI.Vulnerability.Severity) == SeverityScore(matchJ.Vulnerability.Severity) {
					return matchI.Vulnerability.ID > matchJ.Vulnerability.ID
				}
				return SeverityScore(matchI.Vulnerability.Severity) > SeverityScore(matchJ.Vulnerability.Severity)
			}
			return matchI.Artifact.Type < matchJ.Artifact.Type
		}
		return matchI.Artifact.Version < matchJ.Artifact.Version
	}
	return matchI.Artifact.Name < matchJ.Artifact.Name
}

// Swap swaps the elements with indexes i and j.
func (m MatchSort) Swap(i, j int) {
	m[i], m[j] = m[j], m[i]
}
