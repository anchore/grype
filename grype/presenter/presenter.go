package presenter

import (
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/cyclonedx"
	"github.com/anchore/grype/grype/presenter/cyclonedxvex"
	"github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/sarif"
	"github.com/anchore/grype/grype/presenter/table"
	"github.com/anchore/grype/grype/presenter/template"
	"github.com/anchore/grype/grype/vulnerability"
)

// Presenter is the main interface other Presenters need to implement
type Presenter interface {
	Present(io.Writer) error
}

// GetPresenter retrieves a Presenter that matches a CLI option
func GetPresenter(presenterConfig Config, matches match.Matches, ignoredMatches []match.IgnoredMatch, packages []pkg.Package, context pkg.Context, metadataProvider vulnerability.MetadataProvider, appConfig interface{}, dbStatus interface{}) Presenter {
	switch presenterConfig.format {
	case jsonFormat:
		return json.NewPresenter(matches, ignoredMatches, packages, context, metadataProvider, appConfig, dbStatus)
	case tableFormat:
		if presenterConfig.showSuppressed {
			return table.NewPresenter(matches, packages, metadataProvider, ignoredMatches)
		}
		return table.NewPresenter(matches, packages, metadataProvider, nil)
	case cycloneDXFormat:
		return cyclonedx.NewPresenter(matches, packages, context.Source, metadataProvider)
	case embeddedVEXJSON:
		return cyclonedxvex.NewPresenter(matches, packages, context.Source, metadataProvider, true, cdx.BOMFileFormatJSON)
	case embeddedVEXXML:
		return cyclonedxvex.NewPresenter(matches, packages, context.Source, metadataProvider, true, cdx.BOMFileFormatXML)
	case sarifFormat:
		return sarif.NewPresenter(matches, packages, context.Source, metadataProvider)
	case templateFormat:
		return template.NewPresenter(matches, ignoredMatches, packages, context, metadataProvider, appConfig, dbStatus, presenterConfig.templateFilePath)
	default:
		return nil
	}
}
