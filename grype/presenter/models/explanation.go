package models

import (
	_ "embed"
	"fmt"
	"io"
	"text/template"

	"github.com/anchore/grype/grype/match"
)

//go:embed explain_cve.tmpl
var templ string

// ExplainedVulnerability explains a vulnerability match.
// It includes details about all matched artifacts and how they were
// matched.
type ExplainedVulnerability struct {
	VulnerabilityID   string
	Severity          string
	Namespace         string
	Description       string
	VersionConstraint string
	MatchedPackages   []MatchedPackage
	URLs              []string
}

// TODO: this is basically a slice of matches. Is it needed?
// Maybe I need a different way to orient the slice of matches?
// having nice map/reduce functions is the thing that
// trips me up most writing Go code.

type MatchedPackage struct {
	Package     Package
	Details     []MatchDetails
	Explanation string
}

type VulnerabilityExplainer interface {
	ExplainByID(IDs []string) error
	ExplainBySeverity(severity string) error
	ExplainAll() error
}

type vulnerabilityExplainer struct {
	doc   Document
	w     io.Writer
	templ *template.Template
}

func NewVulnerabilityExplainer(doc Document, w io.Writer) VulnerabilityExplainer {
	return &vulnerabilityExplainer{
		doc:   doc,
		w:     w,
		templ: template.Must(template.New("explanation").Parse(templ)),
	}
}

func (e *vulnerabilityExplainer) ExplainByID(IDs []string) error {
	toExplain := make(map[string]ExplainedVulnerability)
	for _, id := range IDs {
		explained := NewExplainedVulnerability(id, e.doc)
		if explained != nil {
			toExplain[id] = *explained
		}
	}
	for _, id := range IDs {
		explained, ok := toExplain[id]
		if !ok {
			continue
		}
		if err := e.templ.Execute(e.w, explained); err != nil {
			return fmt.Errorf("unable to execute template: %w", err)
		}
	}
	return nil
}

func (e *vulnerabilityExplainer) ExplainBySeverity(severity string) error {
	// TODO: implement
	return nil
}

func (e *vulnerabilityExplainer) ExplainAll() error {
	return nil
}

// NewExplainedVulnerability creates a new explained vulnerability.
func NewExplainedVulnerability(vulnerabilityID string, doc Document) *ExplainedVulnerability {
	var specificMatches []Match
	var relatedMatches []Match
	for _, m := range doc.Matches {
		if m.Vulnerability.ID == vulnerabilityID {
			specificMatches = append(specificMatches, m)
		} else {
			for _, r := range m.RelatedVulnerabilities {
				if r.ID == vulnerabilityID {
					relatedMatches = append(relatedMatches, m)
				}
			}
		}
	}
	if len(specificMatches) == 0 {
		return nil
	}
	packages := make([]MatchedPackage, len(specificMatches))
	for i, m := range specificMatches {
		packages[i] = ToMatchedPackage(m)
	}
	var URLs []string
	for _, m := range specificMatches {
		URLs = append(URLs, m.Vulnerability.VulnerabilityMetadata.URLs...)
	}
	var versionConstraint string
	for _, m := range specificMatches {
		for _, d := range m.MatchDetails {
			if mapResult, ok := d.Found.(map[string]interface{}); ok {
				if version, ok := mapResult["versionConstraint"]; ok {
					if stringVersion, ok := version.(string); ok {
						versionConstraint = stringVersion
					}
				}
			}
		}
	}

	return &ExplainedVulnerability{
		VulnerabilityID:   vulnerabilityID,
		Severity:          specificMatches[0].Vulnerability.Severity,
		Namespace:         specificMatches[0].Vulnerability.Namespace,
		Description:       specificMatches[0].Vulnerability.Description,
		VersionConstraint: versionConstraint,
		MatchedPackages:   packages,
		URLs:              append([]string{specificMatches[0].Vulnerability.DataSource}, URLs...),
	}
}

func ToMatchedPackage(m Match) MatchedPackage {
	explanation := ""
	if len(m.MatchDetails) > 0 {
		switch m.MatchDetails[0].Type {
		case string(match.CPEMatch):
			explanation = formatCPEExplanation(m)
		case string(match.ExactIndirectMatch):
			sourceName, sourceVersion := sourcePackageNameAndVersion(m.MatchDetails[0])
			explanation = fmt.Sprintf("Indirect match on source package: This CVE is reported against %s (version %s), the %s of this %s package.", sourceName, sourceVersion, nameForUpstream(string(m.Artifact.Type)), m.Artifact.Type)
		}
	}
	return MatchedPackage{
		Package:     m.Artifact,
		Details:     m.MatchDetails,
		Explanation: explanation,
	}
}

func sourcePackageNameAndVersion(md MatchDetails) (string, string) {
	var name string
	var version string
	if mapResult, ok := md.SearchedBy.(map[string]interface{}); ok {
		if sourcePackage, ok := mapResult["package"]; ok {
			if sourceMap, ok := sourcePackage.(map[string]interface{}); ok {
				if maybeName, ok := sourceMap["name"]; ok {
					name, _ = maybeName.(string)
				}
				if maybeVersion, ok := sourceMap["version"]; ok {
					version, _ = maybeVersion.(string)
				}
			}
		}
	}
	return name, version
}

func formatCPEExplanation(m Match) string {
	found := m.MatchDetails[0].Found
	if mapResult, ok := found.(map[string]interface{}); ok {
		if cpes, ok := mapResult["cpes"]; ok {
			if cpeSlice, ok := cpes.([]interface{}); ok {
				if len(cpeSlice) > 0 {
					return fmt.Sprintf("CPE match on `%s`", cpeSlice[0])
				}
			}
		}
	}
	return ""
}

func nameForUpstream(typ string) string {
	switch typ {
	case "deb":
		return "origin"
	case "rpm":
		return "source RPM"
	}
	return "upstream"
}
