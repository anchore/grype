package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	matches          match.Matches
	ignoredMatches   []match.IgnoredMatch
	packages         []pkg.Package
	context          pkg.Context
	metadataProvider vulnerability.MetadataProvider
	appConfig        interface{}
	dbStatus         interface{}
	outputFilePath   string
}

// NewPresenter creates a new JSON presenter
func NewPresenter(pb models.PresenterConfig, outputFilePath string) *Presenter {
	return &Presenter{
		matches:          pb.Matches,
		ignoredMatches:   pb.IgnoredMatches,
		packages:         pb.Packages,
		metadataProvider: pb.MetadataProvider,
		context:          pb.Context,
		appConfig:        pb.AppConfig,
		dbStatus:         pb.DBStatus,
		outputFilePath:   outputFilePath,
	}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(defaultOutput io.Writer) error {
	output, closer, err := file.GetWriter(defaultOutput, pres.outputFilePath)
	defer func() {
		if closer != nil {
			err := closer()
			if err != nil {
				log.Warnf("unable to write to report destination: %+v", err)
			}
		}
	}()
	if err != nil {
		return err
	}
	doc, err := models.NewDocument(pres.packages, pres.context, pres.matches, pres.ignoredMatches, pres.metadataProvider,
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
