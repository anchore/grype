package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	matches          match.Matches
	packages         []pkg.Package
	context          pkg.Context
	metadataProvider vulnerability.MetadataProvider
}

// NewPresenter is a *Presenter constructor
func NewPresenter(matches match.Matches, packages []pkg.Package, context pkg.Context, metadataProvider vulnerability.MetadataProvider) *Presenter {
	return &Presenter{
		matches:          matches,
		packages:         packages,
		metadataProvider: metadataProvider,
		context:          context,
	}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	doc, err := NewDocument(pres.packages, pres.context, pres.matches, pres.metadataProvider)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}
