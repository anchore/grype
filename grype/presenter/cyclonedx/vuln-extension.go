package cyclonedx

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	syftCDX "github.com/anchore/syft/syft/presenter/cyclonedx"
	"github.com/google/uuid"
)

// Source: https://cyclonedx.org/ext/vulnerability/

// Vulnerability is the actual description of a vulnerable artifact
type Vulnerability struct {
	Ref     string   `xml:"ref,attr"`
	ID      string   `xml:"v:id"`
	Source  Source   `xml:"v:source"`
	Ratings []Rating `xml:"v:ratings>v:rating"`
	// We do not capture Common Weakness Enumeration
	//Cwes            Cwes             `xml:"v:cwes"`
	Description string `xml:"v:description,omitempty"`
	// We don't have recommendations (e.g. "upgrade")
	//Recommendations *Recommendations `xml:"v:recommendations"`
	Advisories *Advisories `xml:"v:advisories,omitempty"`
}

// Component represents the a single software/package that has vulnerabilities.
type Component struct {
	syftCDX.Component
	Vulnerabilities *[]Vulnerability `xml:"v:vulnerabilities>v:vulnerability,omitempty"`
}

// Source is the origin of the vulnerability, like Github Advisories or NVD, along
// with a URL constructed with the vulnerability ID
type Source struct {
	Name string `xml:"name,attr"`
	URL  string `xml:"v:url"`
}

// Rating has information about the intensity of a vulnerability
type Rating struct {
	Score    Score  `xml:"v:score"`
	Severity string `xml:"v:severity,omitempty"`
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
	Advisory []string `xml:"v:advisory"`
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

	// The schema does not allow "Negligible", only allowing the following:
	// 'None', 'Low', 'Medium', 'High', 'Critical', 'Unknown'
	severity := metadata.Severity
	if metadata.Severity == "Negligible" {
		severity = "Low"
	}

	rating.Severity = severity

	v := Vulnerability{
		Ref: uuid.New().URN(),
		ID:  m.Vulnerability.ID,
		Source: Source{
			Name: m.Vulnerability.RecordSource,
			URL:  makeVulnerabilityURL(m.Vulnerability.ID),
		},
		Ratings:     []Rating{rating},
		Description: metadata.Description,
		Advisories: &Advisories{
			Advisory: metadata.Links,
		},
	}

	return v, nil
}

func makeVulnerabilityURL(id string) string {
	if strings.HasPrefix(id, "CVE-") {
		return fmt.Sprintf("http://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", id)
	}
	if strings.HasPrefix(id, "GHSA") {
		return fmt.Sprintf("https://github.com/advisories/%s", id)
	}
	return id
}
