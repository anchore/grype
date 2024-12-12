package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/clio"
	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	id               clio.Identification
	matches          match.Matches
	ignoredMatches   []match.IgnoredMatch
	packages         []pkg.Package
	context          pkg.Context
	metadataProvider v5.VulnerabilityMetadataProvider
	appConfig        interface{}
	dbStatus         interface{}
}

// NewPresenter creates a new JSON presenter
func NewPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		id:               pb.ID,
		matches:          pb.Matches,
		ignoredMatches:   pb.IgnoredMatches,
		packages:         pb.Packages,
		metadataProvider: pb.MetadataProvider,
		context:          pb.Context,
		appConfig:        pb.AppConfig,
		dbStatus:         pb.DBStatus,
	}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	doc, err := models.NewDocument(pres.id, pres.packages, pres.context, pres.matches, pres.ignoredMatches, pres.metadataProvider,
		pres.appConfig, pres.dbStatus)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}
