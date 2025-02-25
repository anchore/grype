package cyclonedx

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// Presenter writes a CycloneDX report from the given Matches and Scope contents
type Presenter struct {
	id               clio.Identification
	results          match.Matches
	packages         []pkg.Package
	src              *source.Description
	metadataProvider vulnerability.MetadataProvider
	format           cyclonedx.BOMFileFormat
	sbom             *sbom.SBOM
}

// NewJSONPresenter is a *Presenter constructor
func NewJSONPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		id:               pb.ID,
		results:          pb.Matches,
		packages:         pb.Packages,
		metadataProvider: pb.MetadataProvider,
		src:              pb.Context.Source,
		sbom:             pb.SBOM,
		format:           cyclonedx.BOMFileFormatJSON,
	}
}

// NewXMLPresenter is a *Presenter constructor
func NewXMLPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		id:               pb.ID,
		results:          pb.Matches,
		packages:         pb.Packages,
		metadataProvider: pb.MetadataProvider,
		src:              pb.Context.Source,
		sbom:             pb.SBOM,
		format:           cyclonedx.BOMFileFormatXML,
	}
}

// Present creates a CycloneDX-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	// note: this uses the syft cyclondx helpers to create
	// a consistent cyclondx BOM across syft and grype
	cyclonedxBOM := cyclonedxhelpers.ToFormatModel(*pres.sbom)

	// empty the tool metadata and add grype metadata
	cyclonedxBOM.Metadata.Tools = &cyclonedx.ToolsChoice{
		Components: &[]cyclonedx.Component{
			{
				Type:    cyclonedx.ComponentTypeApplication,
				Author:  "anchore",
				Name:    pres.id.Name,
				Version: pres.id.Version,
			},
		},
	}

	vulns := make([]cyclonedx.Vulnerability, 0)
	for _, m := range pres.results.Sorted() {
		v, err := NewVulnerability(m, pres.metadataProvider)
		if err != nil {
			continue
		}
		vulns = append(vulns, v)
	}
	cyclonedxBOM.Vulnerabilities = &vulns
	enc := cyclonedx.NewBOMEncoder(output, pres.format)
	enc.SetPretty(true)
	enc.SetEscapeHTML(false)

	return enc.EncodeVersion(cyclonedxBOM, cyclonedxBOM.SpecVersion)
}
