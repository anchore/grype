package cyclonedx

import (
	"encoding/xml"
	"io"

	"github.com/anchore/grype/grype"
)

// The Name of the kind of presenter.
const Name = "cyclonedx"

// Presenter writes a CycloneDX report from the given Catalog and Scope contents
type Presenter struct{}

// NewPresenter is a *Presenter constructor
func NewPresenter() *Presenter {
	return &Presenter{}
}

// Present creates a CycloneDX-based reporting
func (pres *Presenter) Present(output io.Writer, analysis grype.Analysis) error {
	bom, err := NewDocument(analysis.Packages, analysis.Matches, analysis.Context.Source, analysis.MetadataProvider)
	if err != nil {
		return err
	}

	encoder := xml.NewEncoder(output)
	encoder.Indent("", "  ")

	_, err = output.Write([]byte(xml.Header))
	if err != nil {
		return err
	}

	err = encoder.Encode(bom)

	if err != nil {
		return err
	}

	return err
}
