package cyclonedx

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/formats/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// Presenter writes a CycloneDX report from the given Matches and Scope contents
type Presenter struct {
	results          match.Matches
	packages         []pkg.Package
	srcMetadata      *source.Metadata
	metadataProvider vulnerability.MetadataProvider
	format           cyclonedx.BOMFileFormat
	sbom             *sbom.SBOM
}

// NewPresenter is a *Presenter constructor
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
	cyclonedxBOM := cyclonedxhelpers.ToFormatModel(*pres.sbom)
	vulnberabilities := make([]cyclonedx.Vulnerability, 0)
	for m := range pres.results.Enumerate() {
		v, err := NewVulnerability(m, pres.metadataProvider)
		if err != nil {
			continue
		}
		vulnberabilities = append(vulnberabilities, v)
	}
	cyclonedxBOM.Vulnerabilities = &vulnberabilities
	enc := cyclonedx.NewBOMEncoder(output, pres.format)
	enc.SetPretty(true)

	return enc.Encode(cyclonedxBOM)
}
