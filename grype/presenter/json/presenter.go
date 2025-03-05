package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/presenter/models"
)

type Presenter struct {
	id        clio.Identification
	document  models.Document
	appConfig interface{}
	dbStatus  interface{}
	pretty    bool
}

func NewPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		id:        pb.ID,
		document:  pb.Document,
		appConfig: pb.AppConfig,
		dbStatus:  pb.DBStatus,
		pretty:    pb.Pretty,
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
