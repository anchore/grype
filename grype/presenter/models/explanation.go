package models

import (
	_ "embed"
	"fmt"
	"io"
	"strings"
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
	// MatchedPackages   map[string][]MatchedPackage // map of PURL to MatchedPackage
	MatchedPackages []*ExplainedPackageMatch
	URLs            []string
}

// TODO: this is basically a slice of matches. Is it needed?
// Maybe I need a different way to orient the slice of matches?
// having nice map/reduce functions is the thing that
// trips me up most writing Go code.
// Actually what we will do is build a slice of artifacts with
// the same PURL and then group them by PURL.

type MatchedPackage struct {
	Package     Package
	Details     []MatchDetails
	Explanation string
}

type ExplainedPackageMatch struct {
	PURL        string
	Name        string
	Version     string
	Explanation string
	Locations   []LocatedArtifact
}

type LocatedArtifact struct {
	Location   string
	ArtifactId string
	ViaVulnID  string
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
	// TODO: consider grouping all vulnerabilities by CVE ID
	// and then doing this stuff
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

func (e *vulnerabilityExplainer) ExplainBySeverity(minSeverity string) error {
	uniqueSevereIDs := make(map[string]bool)
	severity := vulnerability.ParseSeverity(minSeverity)
	for _, m := range e.doc.Matches {
		if vulnerability.ParseSeverity(metadata.Severity) >= severity {
			uniqueSevereIDs[m.Vulnerability.ID] = true
		}
	}
	var IDs []string
	for id := range uniqueSevereIDs {
		IDs = append(IDs, id)
	}
	return e.ExplainByID(IDs)
}

func (e *vulnerabilityExplainer) ExplainAll() error {
	uniqueIDs := make(map[string]bool)
	for _, m := range e.doc.Matches {
		uniqueIDs[m.Vulnerability.ID] = true
	}
	var IDs []string
	for id := range uniqueIDs {
		IDs = append(IDs, id)
	}
	return e.ExplainByID(IDs)
}

// NewExplainedVulnerability creates a new explained vulnerability.
func NewExplainedVulnerability(vulnerabilityID string, doc Document) *ExplainedVulnerability {
	var directMatches []Match
	var relatedMatches []Match
	for _, m := range doc.Matches {
		// TODO: make the one that matches on the ID always be first?
		if m.Vulnerability.ID == vulnerabilityID {
			directMatches = append(directMatches, m)
		} else {
			for _, r := range m.RelatedVulnerabilities {
				if r.ID == vulnerabilityID {
					relatedMatches = append(relatedMatches, m)
				}
			}
		}
	}
	if len(directMatches) == 0 {
		return nil
	}
	packages := make(map[string]*ExplainedPackageMatch)
	directAndRelatedMatches := append(directMatches, relatedMatches...)
	for _, m := directAndRelatedMatches {
		if m.Artifact.PURL == "" {
			continue
		}
		if explained, ok := packages[m.Artifact.PURL]; ok {
			for _, location := range m.Artifact.Locations {
				via := ""
				if m.Vulnerability.ID != vulnerabilityID {
					via = m.Vulnerability.ID
				}
				explained.Locations = append(explained.Locations, LocatedArtifact{
					Location:   location.RealPath,
					ArtifactId: m.Artifact.ID,
					ViaVulnID:  via,
				})
			}
		} else {
			explained := startExplainedPackageMatch(m)
			packages[m.Artifact.PURL] = &explained
		}
	}
	var URLs []string
	for _, m := range directAndRelatedMatches {
		URLs = append(URLs, m.Vulnerability.VulnerabilityMetadata.URLs...)
	}
	var versionConstraint string
	for _, m := range directMatches {
		// TODO: which version constraint should we use?
		// in other words, which match should win?
		if len(m.Vulnerability.Fix.Versions) == 0 {
			versionConstraint = "all versions"
		}
		if len(m.Vulnerability.Fix.Versions) == 1 {
			versionConstraint = fmt.Sprintf("< %s", m.Vulnerability.Fix.Versions[0])
		}
	}
	var matchedPackages []*ExplainedPackageMatch
	for _, explained := range packages {
		matchedPackages = append(matchedPackages, explained)
	}

	return &ExplainedVulnerability{
		VulnerabilityID: vulnerabilityID,
		// TODO: which severity should we use?
		// in other words, which match should win?
		Severity:          directMatches[0].Vulnerability.Severity,
		Namespace:         directMatches[0].Vulnerability.Namespace,
		Description:       strings.TrimSpace(directMatches[0].Vulnerability.Description),
		VersionConstraint: versionConstraint,
		MatchedPackages:   matchedPackages,
		URLs:              dedupeURLs(directMatches[0].Vulnerability.DataSource, URLs),
	}
}

func startExplainedPackageMatch(m Match) ExplainedPackageMatch {
	explanation := ""
	if len(m.MatchDetails) > 0 {
		switch m.MatchDetails[0].Type {
		case string(match.CPEMatch):
			explanation = formatCPEExplanation(m)
		case string(match.ExactIndirectMatch):
			sourceName, sourceVersion := sourcePackageNameAndVersion(m.MatchDetails[0])
			explanation = fmt.Sprintf("Note: This CVE is reported against %s (version %s), the %s of this %s package.", sourceName, sourceVersion, nameForUpstream(string(m.Artifact.Type)), m.Artifact.Type)
		}
	}
	var locatedArtifacts []LocatedArtifact
	for _, location := range m.Artifact.Locations {
		locatedArtifacts = append(locatedArtifacts, LocatedArtifact{
			Location:   location.RealPath,
			ArtifactId: m.Artifact.ID,
		})
	}
	return ExplainedPackageMatch{
		PURL:        m.Artifact.PURL,
		Name:        m.Artifact.Name,
		Version:     m.Artifact.Version,
		Explanation: explanation,
		Locations:   locatedArtifacts,
	}
}

func dedupeURLs(showFirst string, rest []string) []string {
	var result []string
	result = append(result, showFirst)
	deduplicate := make(map[string]bool)
	for _, u := range rest {
		if _, ok := deduplicate[u]; !ok && u != showFirst {
			result = append(result, u)
			deduplicate[u] = true
		}
	}
	return result
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
	searchedBy := m.MatchDetails[0].SearchedBy
	if mapResult, ok := searchedBy.(map[string]interface{}); ok {
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
