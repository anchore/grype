package presenter

import (
	"io"

	"github.com/anchore/syft/syft/distro"

	"github.com/anchore/grype/grype/match"

	"github.com/anchore/grype/grype/vulnerability"

	"github.com/anchore/grype/grype/presenter/cyclonedx"
	"github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/table"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Presenter is the main interface other Presenters need to implement
type Presenter interface {
	Present(io.Writer) error
}

// GetPresenter retrieves a Presenter that matches a CLI option
func GetPresenter(option Option, matches match.Matches, catalog *pkg.Catalog, d *distro.Distro, srcMetadata source.Metadata, metadataProvider vulnerability.MetadataProvider) Presenter {
	switch option {
	case JSONPresenter:
		return json.NewPresenter(matches, catalog, d, srcMetadata, metadataProvider)
	case TablePresenter:
		return table.NewPresenter(matches, catalog, metadataProvider)
	case CycloneDxPresenter:
		return cyclonedx.NewPresenter(matches, catalog, srcMetadata, metadataProvider)
	default:
		return nil
	}
}
