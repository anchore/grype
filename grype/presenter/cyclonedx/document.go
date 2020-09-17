package cyclonedx

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/pkg"
	syftCDX "github.com/anchore/syft/syft/presenter/cyclonedx"
	"github.com/google/uuid"
)

// Source: https://github.com/CycloneDX/specification

// Document represents a CycloneDX Vulnerability Document.
type Document struct {
	XMLName       xml.Name               `xml:"bom"`
	XMLNs         string                 `xml:"xmlns,attr"`
	Version       int                    `xml:"version,attr"`
	SerialNumber  string                 `xml:"serialNumber,attr"`
	Components    []Component            `xml:"components>component"`
	BomDescriptor *syftCDX.BomDescriptor `xml:"bd:metadata"` // The BOM descriptor extension
}

// NewDocument returns an empty CycloneDX Document object.
func NewDocument() Document {
	return Document{
		XMLNs:        "http://cyclonedx.org/schema/bom/1.2",
		Version:      1,
		SerialNumber: uuid.New().URN(),
	}
}

// NewVulnerability creates a Vulnerability document from a match and the metadata provider
func NewVulnerability(m match.Match, p vulnerability.MetadataProvider) (Vulnerability, error) {
	metadata, err := p.GetMetadata(m.Vulnerability.ID, m.Vulnerability.RecordSource)
	if err != nil {
		return Vulnerability{}, fmt.Errorf("unable to fetch vuln=%q metadata: %+v", m.Vulnerability.ID, err)
	}

	// The spec allows many ratings, but we only have 1
	var rating Rating
	var score Score

	if metadata.CvssV2 != nil {
		if metadata.CvssV2.ExploitabilityScore > 0 {
			score.Exploitability = metadata.CvssV2.ExploitabilityScore
		}
		if metadata.CvssV2.ImpactScore > 0 {
			score.Impact = metadata.CvssV2.ImpactScore
		}
		score.Base = metadata.CvssV2.BaseScore
		rating.Method = "CVSSv2"
		rating.Vector = metadata.CvssV2.Vector
	}

	if metadata.CvssV3 != nil {
		if metadata.CvssV3.ExploitabilityScore > 0 {
			score.Exploitability = metadata.CvssV3.ExploitabilityScore
		}
		if metadata.CvssV3.ImpactScore > 0 {
			score.Impact = metadata.CvssV3.ImpactScore
		}
		score.Base = metadata.CvssV3.BaseScore
		rating.Method = "CVSSv3"
		rating.Vector = metadata.CvssV3.Vector
	}

	rating.Score = score
	rating.Severity = metadata.Severity

	v := Vulnerability{
		Ref: uuid.New().URN(),
		ID:  m.Vulnerability.ID,
		Source: Source{
			Name: m.Vulnerability.RecordSource,
			URL:  makeURL(m.Vulnerability.ID),
		},
		Ratings:     []Rating{rating},
		Description: metadata.Description,
		Advisories: &Advisories{
			Advisory: metadata.Links,
		},
	}

	return v, nil
}

// NewDocumentFromCatalog returns a CycloneDX Document object populated with the vulnerability contents.
func NewDocumentFromCatalog(catalog *pkg.Catalog, matches match.Matches, provider vulnerability.MetadataProvider) Document {
	bom := NewDocument()
	for p := range catalog.Enumerate() {
		// make a new compoent (by value)
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
			for _, m := range pkgMatches {
				// Sort of eating up the error here, we are appending only when there is
				// no error. When there is one, we ignore it and move to the next vuln
				// An error is only possible if it metadata can't be produced
				v, err := NewVulnerability(m, provider)
				if err == nil {
					component.Vulnerabilities = append(component.Vulnerabilities, v)
				}
			}
		}

		// add a *copy* of the component to the bom document
		bom.Components = append(bom.Components, component)
	}

	bom.BomDescriptor = syftCDX.NewBomDescriptor()

	return bom
}

func makeURL(id string) string {
	if strings.HasPrefix(id, "CVE-") {
		return fmt.Sprintf("http://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", id)
	}
	if strings.HasPrefix(id, "GHSA") {
		return fmt.Sprintf("https://github.com/advisories/%s", id)
	}
	return id
}
