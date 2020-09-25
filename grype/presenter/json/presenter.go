package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/grype/grype/match"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	matches          match.Matches
	catalog          *pkg.Catalog
	scope            scope.Scope
	metadataProvider vulnerability.MetadataProvider
}

// NewPresenter is a *Presenter constructor
func NewPresenter(matches match.Matches, catalog *pkg.Catalog, theScope scope.Scope, metadataProvider vulnerability.MetadataProvider) *Presenter {
	return &Presenter{
		matches:          matches,
		catalog:          catalog,
		metadataProvider: metadataProvider,
		scope:            theScope,
	}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	doc, err := NewDocument(pres.catalog, pres.scope, pres.matches, pres.metadataProvider)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}
