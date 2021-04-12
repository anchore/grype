package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/grype/grype"

	"github.com/anchore/grype/grype/presenter/models"
)

// The Name of the kind of presenter.
const Name = "json"

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct{}

// NewPresenter is a *Presenter constructor
func NewPresenter() *Presenter {
	return &Presenter{}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer, analysis grype.Analysis) error {
	doc, err := models.NewDocument(analysis)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}
