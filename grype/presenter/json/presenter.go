package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/grype/grype/result"
	"github.com/anchore/syft/syft/pkg"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	results result.Result
	catalog *pkg.Catalog
}

// NewPresenter is a *Presenter constructor
func NewPresenter(results result.Result, catalog *pkg.Catalog) *Presenter {
	return &Presenter{
		results: results,
		catalog: catalog,
	}
}

// ResultObj is a single item for the JSON array reported
type ResultObj struct {
	Cve     string  `json:"cve"`
	FoundBy FoundBy `json:"found-by"`
	Package Package `json:"package"`
}

// FoundBy contains all data that indicates how the result match was found
type FoundBy struct {
	Matcher   string `json:"matcher"`
	SearchKey string `json:"search-key"`
}

// Package is a nested JSON object from ResultObj
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	doc := make([]ResultObj, 0)

	for match := range pres.results.Enumerate() {
		p := pres.catalog.Package(match.Package.ID())
		doc = append(
			doc,
			ResultObj{
				Cve: match.Vulnerability.ID,
				FoundBy: FoundBy{
					Matcher:   match.Matcher.String(),
					SearchKey: match.SearchKey,
				},
				Package: Package{Name: p.Name, Version: p.Version, Type: p.Type.String()},
			},
		)
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}
