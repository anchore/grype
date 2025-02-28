package cyclonedx

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// Presenter writes a CycloneDX report from the given Matches and Scope contents
type Presenter struct {
	id       clio.Identification
	document models.Document
	src      source.Description
	format   cyclonedx.BOMFileFormat
	sbom     *sbom.SBOM
}

// NewJSONPresenter is a *Presenter constructor
func NewJSONPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		id:       pb.ID,
		document: pb.Document,
		src:      pb.SBOM.Source,
		sbom:     pb.SBOM,
		format:   cyclonedx.BOMFileFormatJSON,
	}
}

// NewXMLPresenter is a *Presenter constructor
func NewXMLPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		id:       pb.ID,
		document: pb.Document,
		src:      pb.SBOM.Source,
		sbom:     pb.SBOM,
		format:   cyclonedx.BOMFileFormatXML,
	}
}

// Present creates a CycloneDX-based reporting
func (p *Presenter) Present(output io.Writer) error {
	// note: this uses the syft cyclondx helpers to create
	// a consistent cyclondx BOM across syft and grype
	cyclonedxBOM := cyclonedxhelpers.ToFormatModel(*p.sbom)

	// empty the tool metadata and add grype metadata
	cyclonedxBOM.Metadata.Tools = &cyclonedx.ToolsChoice{
		Components: &[]cyclonedx.Component{
			{
				Type:    cyclonedx.ComponentTypeApplication,
				Author:  "anchore",
				Name:    p.id.Name,
				Version: p.id.Version,
			},
		},
	}

	vulns := make([]cyclonedx.Vulnerability, 0)
	for _, m := range p.document.Matches {
		v, err := NewVulnerability(m)
		if err != nil {
			continue
		}
		vulns = append(vulns, v)
	}
	cyclonedxBOM.Vulnerabilities = &vulns
	enc := cyclonedx.NewBOMEncoder(output, p.format)
	enc.SetPretty(true)
	enc.SetEscapeHTML(false)

	return enc.EncodeVersion(cyclonedxBOM, cyclonedxBOM.SpecVersion)
}
