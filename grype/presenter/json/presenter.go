package json

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/grype/grype/match"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/pkg"
	syftJson "github.com/anchore/syft/syft/presenter/json"
	"github.com/anchore/syft/syft/scope"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	results          match.Matches
	catalog          *pkg.Catalog
	scope            scope.Scope
	metadataProvider vulnerability.MetadataProvider
}

// NewPresenter is a *Presenter constructor
func NewPresenter(results match.Matches, catalog *pkg.Catalog, theScope scope.Scope, metadataProvider vulnerability.MetadataProvider) *Presenter {
	return &Presenter{
		results:          results,
		catalog:          catalog,
		metadataProvider: metadataProvider,
		scope:            theScope,
	}
}

// Finding is a single item for the JSON array reported
type Finding struct {
	Vulnerability Vulnerability     `json:"vulnerability"`
	MatchDetails  MatchDetails      `json:"match-details"`
	Artifact      syftJson.Artifact `json:"artifact"`
}

// MatchDetails contains all data that indicates how the result match was found
type MatchDetails struct {
	Matcher   string                 `json:"matcher"`
	SearchKey map[string]interface{} `json:"search-key"`
	MatchInfo map[string]interface{} `json:"matched-on"`
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	doc := make([]Finding, 0)

	for m := range pres.results.Enumerate() {
		p := pres.catalog.Package(m.Package.ID())

		art, err := syftJson.NewArtifact(p, pres.scope)
		if err != nil {
			return err
		}

		metadata, err := pres.metadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.RecordSource)
		if err != nil {
			return fmt.Errorf("unable to fetch vuln=%q metadata: %+v", m.Vulnerability.ID, err)
		}

		doc = append(
			doc,
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

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}
