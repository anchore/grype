package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/grype/grype/presenter/models"
)

type Presenter struct {
	document models.Document
	pretty   bool
}

func NewPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		document: pb.Document,
		pretty:   pb.Pretty,
	}
}

func (p *Presenter) Present(output io.Writer) error {
	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	if p.pretty {
		enc.SetIndent("", " ")
	}
	return enc.Encode(&p.document)
}
