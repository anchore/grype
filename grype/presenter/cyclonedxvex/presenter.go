package cyclonedxvex

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// Presenter writes a CycloneDX report from the given Matches and Scope contents
type Presenter struct {
	results          match.Matches
	packages         []pkg.Package
	metadataProvider vulnerability.MetadataProvider
	srcMetadata      *source.Metadata
	sbom             *sbom.SBOM
	format           cyclonedx.BOMFileFormat
}

func NewPresenter(pb models.PresenterBundle, format cyclonedx.BOMFileFormat) *Presenter {
	return &Presenter{
		results:          pb.Matches,
		packages:         pb.Packages,
		metadataProvider: pb.MetadataProvider,
		srcMetadata:      pb.Context.Source,
		sbom:             pb.SBOM,
		format:           format,
	}
}

// Present creates a CycloneDX-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	// update to use syft library
	return nil
}
