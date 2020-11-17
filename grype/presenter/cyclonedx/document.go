package cyclonedx

import (
	"encoding/xml"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/version"
	"github.com/anchore/syft/syft/pkg"
	syftCDX "github.com/anchore/syft/syft/presenter/cyclonedx"
	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

// Source: https://github.com/CycloneDX/specification

// Document represents a CycloneDX Vulnerability Document.
type Document struct {
	XMLName       xml.Name               `xml:"bom"`
	XMLNs         string                 `xml:"xmlns,attr"`
	XMLNsBd       string                 `xml:"xmlns:bd,attr"`
	XMLNsV        string                 `xml:"xmlns:v,attr"`
	Version       int                    `xml:"version,attr"`
	SerialNumber  string                 `xml:"serialNumber,attr"`
	Components    []Component            `xml:"components>component"`
	BomDescriptor *syftCDX.BomDescriptor `xml:"bd:metadata"` // The BOM descriptor extension
}

// NewDocument returns an empty CycloneDX Document object.
func NewDocument(catalog *pkg.Catalog, matches match.Matches, srcMetadata source.Metadata, provider vulnerability.MetadataProvider) (Document, error) {
	versionInfo := version.FromBuild()

	doc := Document{
		XMLNs:         "http://cyclonedx.org/schema/bom/1.2",
		XMLNsBd:       "http://cyclonedx.org/schema/ext/bom-descriptor/1.0",
		XMLNsV:        "http://cyclonedx.org/schema/ext/vulnerability/1.0",
		Version:       1,
		SerialNumber:  uuid.New().URN(),
		BomDescriptor: syftCDX.NewBomDescriptor(internal.ApplicationName, versionInfo.Version, srcMetadata),
	}

	// attach matches

	for p := range catalog.Enumerate() {
		// make a new component (by value)
		component := Component{
			Component: syftCDX.Component{
				Type:    "library", // TODO: this is not accurate, syft does the same thing
				Name:    p.Name,
				Version: p.Version,
			},
		}

		var licenses []syftCDX.License
		for _, licenseName := range p.Licenses {
			licenses = append(licenses, syftCDX.License{
				Name: licenseName,
			})
		}
		if len(licenses) > 0 {
			// adding licenses to the component
			component.Component.Licenses = &licenses
		}

		// mutate the component

		pkgMatches := matches.GetByPkgID(p.ID())

		if len(pkgMatches) > 0 {
			var vulnerabilities []Vulnerability
			for _, m := range pkgMatches {
				// Sort of eating up the error here, we are appending only when there is
				// no error. When there is one, we ignore it and move to the next vuln
				// An error is only possible if it metadata can't be produced
				v, err := NewVulnerability(m, provider)
				if err != nil {
					return Document{}, err
				}
				vulnerabilities = append(vulnerabilities, v)
			}
			component.Vulnerabilities = &vulnerabilities
		}

		// add a *copy* of the component to the bom document
		doc.Components = append(doc.Components, component)
	}

	return doc, nil
}
