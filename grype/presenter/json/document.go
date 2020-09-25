package json

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/pkg"
	syftJson "github.com/anchore/syft/syft/presenter/json"
	"github.com/anchore/syft/syft/scope"
)

// Document represents the JSON document to be presented
type Document struct {
	Findings  []Finding       `json:"vulnerabilities"`
	Image     *syftJson.Image `json:"image,omitempty"`
	Directory *string         `json:"directory,omitempty"`
}

// Finding is a single item for the JSON array reported
type Finding struct {
	Vulnerability Vulnerability     `json:"vulnerability"`
	MatchDetails  MatchDetails      `json:"matchDetails"`
	Artifact      syftJson.Artifact `json:"artifact"`
}

// MatchDetails contains all data that indicates how the result match was found
type MatchDetails struct {
	Matcher   string                 `json:"matcher"`
	SearchKey map[string]interface{} `json:"searchKey"`
	MatchInfo map[string]interface{} `json:"matchedOn"`
}

// NewDocument creates and populates a new Document struct, representing the populated JSON document.
func NewDocument(catalog *pkg.Catalog, s scope.Scope, matches match.Matches, metadataProvider vulnerability.MetadataProvider) (Document, error) {
	doc := Document{}

	srcObj := s.Source()
	switch src := srcObj.(type) {
	case scope.ImageSource:
		doc.Image = syftJson.NewImage(src)
	case scope.DirSource:
		doc.Directory = &s.DirSrc.Path
	default:
		return Document{}, fmt.Errorf("unsupported source: %T", src)
	}

	// we must preallocate the findings to ensure the JSON document does not show "null" when no matches are found
	var findings = make([]Finding, 0)
	for m := range matches.Enumerate() {
		p := catalog.Package(m.Package.ID())
		art, err := syftJson.NewArtifact(p, s)
		if err != nil {
			return Document{}, err
		}

		metadata, err := metadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.RecordSource)
		if err != nil {
			return Document{}, fmt.Errorf("unable to fetch vuln=%q metadata: %+v", m.Vulnerability.ID, err)
		}

		findings = append(
			findings,
			Finding{
				Vulnerability: NewVulnerability(m, metadata),
				Artifact:      art,
				MatchDetails: MatchDetails{
					Matcher:   m.Matcher.String(),
					SearchKey: m.SearchKey,
					MatchInfo: m.SearchMatches,
				},
			},
		)
	}
	doc.Findings = findings

	return doc, nil
}
