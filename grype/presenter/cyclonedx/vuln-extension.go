package cyclonedx

import (
	"encoding/xml"
	"time"

	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/version"
	syftCDX "github.com/anchore/syft/syft/presenter/cyclonedx"
)

// Source: https://cyclonedx.org/ext/vulnerability/

// Source is the origin of the vulnerability, like Github Advisories or NVD, along
// with a URL constructed with the vulnerability ID
type Source struct {
	Name string `xml:"v:name,attr"`
	URL  string `xml:"v:url"`
}

// Rating has information about the intensity of a vulnerability
type Rating struct {
	Score    Score  `xml:"v:score"`
	Severity string `xml:"v:severity"`
	Method   string `xml:"v:method,omitempty"`
	Vector   string `xml:"v:vector,omitempty"`
}

// Score provides the different ways to measure how serious a vulnerability is
type Score struct {
	Base           float64 `xml:"v:base"`
	Impact         float64 `xml:"v:impact"`
	Exploitability float64 `xml:"v:exploitability"`
}

// Advisories holds all the links for a vulnerability
type Advisories struct {
	Advisory []string `xml:"advisory"`
}

// Vulnerability is the actual description of a vulnerable artifact
type Vulnerability struct {
	Ref     string   `xml:"ref,attr"`
	ID      string   `xml:"v:id"`
	Source  Source   `xml:"v:source"`
	Ratings []Rating `xml:"v:ratings"`
	// We do not capture Common Weakness Enumeration
	//Cwes            Cwes             `xml:"v:cwes"`
	Description string `xml:"v:description,omitempty"`
	// We don't have recommendations (e.g. "upgrade")
	//Recommendations *Recommendations `xml:"v:recommendations"`
	Advisories *Advisories `xml:"v:advisories"`
}

// Component represents the a single software/package that has vulnerabilities.
type Component struct {
	syftCDX.Component
	Vulnerabilities []Vulnerability `xml:"v:vulnerabilities"`
}

// NewBomDescriptor returns a new BomDescriptor tailored for the current time and "syft" tool details.
func NewBomDescriptor() *syftCDX.BomDescriptor {
	versionInfo := version.FromBuild()
	return &syftCDX.BomDescriptor{
		XMLName:   xml.Name{},
		Timestamp: time.Now().Format(time.RFC3339),
		Tool: &syftCDX.BdTool{
			Vendor:  "anchore",
			Name:    internal.ApplicationName,
			Version: versionInfo.Version,
		},
	}
}
