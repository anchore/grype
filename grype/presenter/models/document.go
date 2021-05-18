package models

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/version"
)

// Document represents the JSON document to be presented
type Document struct {
	Matches    []Match      `json:"matches"`
	Source     *source      `json:"source"`
	Distro     distribution `json:"distro"`
	Descriptor descriptor   `json:"descriptor"`
}

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

// NewDocument creates and populates a new Document struct, representing the populated JSON document.
func NewDocument(packages []pkg.Package, context pkg.Context, matches match.Matches,
	metadataProvider vulnerability.MetadataProvider, appConfig interface{}, dbStatus interface{}) (Document, error) {
	// we must preallocate the findings to ensure the JSON document does not show "null" when no matches are found
	var findings = make([]Match, 0)
	for _, m := range matches.Sorted() {
		p := pkg.ByID(m.Package.ID(), packages)
		if p == nil {
			return Document{}, fmt.Errorf("unable to find package in collection: %+v", p)
		}

		relatedVulnerabilities := make([]VulnerabilityMetadata, len(m.Vulnerability.RelatedVulnerabilities))
		for idx, r := range m.Vulnerability.RelatedVulnerabilities {
			relatedMetadata, err := metadataProvider.GetMetadata(r.ID, r.Namespace)
			if err != nil {
				return Document{}, fmt.Errorf("unable to fetch related vuln=%q metadata: %+v", r, err)
			}
			if relatedMetadata != nil {
				relatedVulnerabilities[idx] = NewVulnerabilityMetadata(r.ID, r.Namespace, relatedMetadata)
			}
		}

		metadata, err := metadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.Namespace)
		if err != nil {
			return Document{}, fmt.Errorf("unable to fetch vuln=%q metadata: %+v", m.Vulnerability.ID, err)
		}

		findings = append(
			findings,
			Match{
				Vulnerability:          NewVulnerability(m.Vulnerability, metadata),
				Artifact:               newPackage(*p),
				RelatedVulnerabilities: relatedVulnerabilities,
				MatchDetails: MatchDetails{
					Matcher:    m.Matcher.String(),
					SearchedBy: m.SearchKey,
					MatchedOn:  m.SearchMatches,
				},
			},
		)
	}

	var src *source
	if context.Source != nil {
		theSrc, err := newSource(*context.Source)
		if err != nil {
			return Document{}, err
		}
		src = &theSrc
	}

	return Document{
		Matches: findings,
		Source:  src,
		Distro:  newDistribution(context.Distro),
		Descriptor: descriptor{
			Name:                  internal.ApplicationName,
			Version:               version.FromBuild().Version,
			Configuration:         appConfig,
			VulnerabilityDbStatus: dbStatus,
		},
	}, nil
}
