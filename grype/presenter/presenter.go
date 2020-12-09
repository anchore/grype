package presenter

import (
	"io"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/cyclonedx"
	"github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/table"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/source"
)

// Presenter is the main interface other Presenters need to implement
type Presenter interface {
	Present(io.Writer) error
}

// GetPresenter retrieves a Presenter that matches a CLI option
func GetPresenter(option Option, matches match.Matches, packages []pkg.Package, d *distro.Distro, srcMetadata source.Metadata, metadataProvider vulnerability.MetadataProvider) Presenter {
	switch option {
	case JSONPresenter:
		return json.NewPresenter(matches, packages, d, srcMetadata, metadataProvider)
	case TablePresenter:
		return table.NewPresenter(matches, packages, metadataProvider)
	case CycloneDxPresenter:
		return cyclonedx.NewPresenter(matches, packages, srcMetadata, metadataProvider)
	default:
		return nil
	}
}
