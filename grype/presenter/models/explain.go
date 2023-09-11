package models

import (
	_ "embed"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/template"

	"github.com/anchore/grype/grype/match"
)

//go:embed explain_cve_new.tmpl
var explainTemplate string

// TODO: basically re-write a lot of this
// Build a structure where an ExplainedVulnerability
// is basically the nvd:cpe record, plus a list of
// records that relate up to it. The convert that
// record to the ExplainViewModel building a list
// of artifacts we matched and why, and then
// render it either as JSON or as the template.

type ExplainViewModel struct {
	PrimaryVulnerability   VulnerabilityMetadata
	RelatedVulnerabilities []VulnerabilityMetadata
	MatchedPackages        []*ExplainedPackage
	URLs                   []string
}

type ExplainViewModelBuilder struct {
	PrimaryVulnerability Vulnerability // this is the vulnerability we're trying to explain
	PrimaryMatch         Match
	RelatedMatches       []Match
}

type ExplainedFindings map[string]ExplainViewModel

type ExplainedPackage struct {
	PURL                string
	Name                string
	Version             string // TODO: is there only going to be one of these?
	MatchedOnID         string
	MatchedOnNamespace  string
	IndirectExplanation string
	CPEExplanation      string
	Locations           []ExplainedEvidence
}

type ExplainedEvidence struct {
	Location     string
	ArtifactId   string
	ViaVulnID    string
	ViaNamespace string
}

type betterVulnerabilityExplainer struct {
	w   io.Writer
	doc *Document
}

func NewBetterVulnerabilityExplainer(w io.Writer, doc *Document) VulnerabilityExplainer {
	return &betterVulnerabilityExplainer{
		w:   w,
		doc: doc,
	}
}

var funcs = template.FuncMap{
	"trim": strings.TrimSpace,
}

func (e *betterVulnerabilityExplainer) ExplainByID(IDs []string) error {
	// TODO: requested ID is always the primary match
	findings, err := ExplainDoc(e.doc, IDs)
	if err != nil {
		return err
	}
	t := template.Must(template.New("explanation").Funcs(funcs).Parse(explainTemplate))
	for _, id := range IDs {
		finding, ok := findings[id]
		if !ok {
			continue
		}
		if err := t.Execute(e.w, finding); err != nil {
			return fmt.Errorf("unable to execute template: %w", err)
		}
	}
	return nil
}

func (e *betterVulnerabilityExplainer) ExplainBySeverity(severity string) error {
	return fmt.Errorf("not implemented")
}

func (e *betterVulnerabilityExplainer) ExplainAll() error {
	findings, err := ExplainDoc(e.doc, nil)
	if err != nil {
		return err
	}
	t := template.Must(template.New("explanation").Funcs(funcs).Parse(explainTemplate))

	return t.Execute(e.w, findings)
}

func ExplainDoc(doc *Document, requestedIDs []string) (ExplainedFindings, error) {
	result := make(ExplainedFindings)
	builders := make(map[string]*ExplainViewModelBuilder)
	for _, m := range doc.Matches {
		key := m.Vulnerability.ID
		existing, ok := builders[key]
		if !ok {
			existing = NewExplainedVulnerabilityBuilder()
			builders[m.Vulnerability.ID] = existing
		}
		existing.WithMatch(m, requestedIDs, false)
	}
	for _, m := range doc.Matches {
		for _, related := range m.RelatedVulnerabilities {
			key := related.ID
			existing, ok := builders[key]
			if !ok {
				existing = NewExplainedVulnerabilityBuilder()
				builders[key] = existing
			}
			existing.WithMatch(m, requestedIDs, false)
		}
	}
	for k, v := range builders {
		result[k] = v.Build()
	}
	return result, nil
}

func NewExplainedVulnerabilityBuilder() *ExplainViewModelBuilder {
	return &ExplainViewModelBuilder{}
}

// WithMatch adds a match to the builder
// accepting enough information to determine whether the match is a primary match or a related match
func (b *ExplainViewModelBuilder) WithMatch(m Match, userRequestedIDs []string, graphIsByCVE bool) {
	// TODO: check if it's a primary vulnerability
	// (the below checks if it's a primary _match_, which is wrong)
	if b.isPrimaryAdd(m, userRequestedIDs, graphIsByCVE) {
		// Demote the current primary match to related match
		// if it exists
		if b.PrimaryMatch.Vulnerability.ID != "" {
			b.WithRelatedMatch(b.PrimaryMatch)
		}
		b.WithPrimaryMatch(m)
	} else {
		b.WithRelatedMatch(m)
	}
}

func (b *ExplainViewModelBuilder) isPrimaryAdd(candidate Match, userRequestedIDs []string, graphIsByCVE bool) bool {
	// TODO: "primary" is a property of a vulnerability, not a match
	// if there's not currently any match, make this one primary since we don't know any better
	if b.PrimaryMatch.Vulnerability.ID == "" {
		return true
	}
	// There is a primary match, so we need to determine if the candidate is "more primary"
	if graphIsByCVE {
		panic("not implemented") // by-cve graphs are upside down.
	}
	idWasRequested := false
	for _, id := range userRequestedIDs {
		if candidate.Vulnerability.ID == id {
			idWasRequested = true
			break
		}
	}
	// We're making graphs of specifically requested IDs, and the user didn't ask about
	// this ID, so it can't be primary
	if !idWasRequested && len(userRequestedIDs) > 0 {
		return false
	}
	// Either the user didn't ask for specific IDs, or the candidate has an ID the user asked for.
	currentPrimaryIsChildOfCandidate := false
	for _, related := range b.PrimaryMatch.RelatedVulnerabilities {
		if related.ID == candidate.Vulnerability.ID {
			currentPrimaryIsChildOfCandidate = true
			break
		}
	}
	if currentPrimaryIsChildOfCandidate {
		return true
	}
	return false
}

func (b *ExplainViewModelBuilder) WithPrimaryMatch(m Match) *ExplainViewModelBuilder {
	b.PrimaryMatch = m
	return b
}

func (b *ExplainViewModelBuilder) WithRelatedMatch(m Match) *ExplainViewModelBuilder {
	b.RelatedMatches = append(b.RelatedMatches, m)
	return b
}

func (b *ExplainViewModelBuilder) Build() ExplainViewModel {
	URLs := b.PrimaryMatch.Vulnerability.URLs
	URLs = append(URLs, b.PrimaryMatch.Vulnerability.DataSource)
	for _, v := range b.PrimaryMatch.RelatedVulnerabilities {
		URLs = append(URLs, v.URLs...)
		URLs = append(URLs, v.DataSource)
	}
	for _, m := range b.RelatedMatches {
		URLs = append(URLs, m.Vulnerability.URLs...)
		for _, v := range m.RelatedVulnerabilities {
			URLs = append(URLs, v.URLs...)
			URLs = append(URLs, v.DataSource)
		}
	}

	pURLsToMatchDetails := make(map[string]*ExplainedPackage)
	for _, m := range append(b.RelatedMatches, b.PrimaryMatch) {
		key := m.Artifact.PURL
		// TODO: match details can match multiple packages
		var newLocations []ExplainedEvidence
		for _, l := range m.Artifact.Locations {
			newLocations = append(newLocations, ExplainedEvidence{
				Location:     l.RealPath,
				ArtifactId:   m.Artifact.ID, // TODO: this is sometimes blank. Why?
				ViaVulnID:    m.Vulnerability.ID,
				ViaNamespace: m.Vulnerability.Namespace,
			})
		}
		// TODO: how can match details explain locations?
		// Like, I have N matchDetails, and N locations, but I don't know which matchDetail explains which location
		var indirectExplanation string
		var cpeExplanation string
		for i, md := range m.MatchDetails {
			explanation := explainMatchDetail(m, i)
			if explanation != "" {
				if md.Type == string(match.CPEMatch) {
					cpeExplanation = explanation
				}
				if md.Type == string(match.ExactIndirectMatch) {
					indirectExplanation = explanation
				}
			}
		}
		e, ok := pURLsToMatchDetails[key]
		if !ok {
			e = &ExplainedPackage{
				PURL:                m.Artifact.PURL,
				Name:                m.Artifact.Name,
				Version:             m.Artifact.Version,
				MatchedOnID:         m.Vulnerability.ID,
				MatchedOnNamespace:  m.Vulnerability.Namespace,
				IndirectExplanation: indirectExplanation,
				CPEExplanation:      cpeExplanation,
				Locations:           newLocations,
			}
			pURLsToMatchDetails[key] = e
		} else {
			// TODO: what if MatchedOnID and MatchedOnNamespace are different?
			e.Locations = append(e.Locations, newLocations...)
			if e.CPEExplanation == "" {
				e.CPEExplanation = cpeExplanation
			}
			if e.IndirectExplanation == "" {
				e.IndirectExplanation = indirectExplanation
			}
			// e.Explanations = append(e.Explanations, newExplanations...)
			// if e.MatchedOnID != m.Vulnerability.ID || e.MatchedOnNamespace != m.Vulnerability.Namespace {
			// 	// TODO: do something smart.
			// 	panic("matched on different vulnerabilities")
			// }
		}
	}
	var sortPURLs []string
	for k := range pURLsToMatchDetails {
		sortPURLs = append(sortPURLs, k)
	}
	sort.Strings(sortPURLs)
	var explainedPackages []*ExplainedPackage
	for _, k := range sortPURLs {
		explainedPackages = append(explainedPackages, pURLsToMatchDetails[k])
	}

	// TODO: this isn't right at all.
	// We need to be able to add related vulnerabilities
	var relatedVulnerabilities []VulnerabilityMetadata
	var dedupeRelatedVulnerabilities = make(map[string]VulnerabilityMetadata)
	var sortDedupedRelatedVulnerabilities []string
	for _, m := range append(b.RelatedMatches, b.PrimaryMatch) {
		key := fmt.Sprintf("%s:%s", m.Vulnerability.Namespace, m.Vulnerability.ID)
		dedupeRelatedVulnerabilities[key] = m.Vulnerability.VulnerabilityMetadata
		for _, r := range m.RelatedVulnerabilities {
			key := fmt.Sprintf("%s:%s", r.Namespace, r.ID)
			dedupeRelatedVulnerabilities[key] = r
		}
	}
	var primaryVulnerability VulnerabilityMetadata
	for _, r := range dedupeRelatedVulnerabilities {
		if r.ID == b.PrimaryMatch.Vulnerability.ID && r.Namespace == "nvd:cpe" {
			primaryVulnerability = r
		}
	}
	if primaryVulnerability.ID == "" {
		primaryVulnerability = b.PrimaryMatch.Vulnerability.VulnerabilityMetadata
	}
	primaryURL := primaryVulnerability.DataSource

	// delete the primary vulnerability from the related vulnerabilities
	delete(dedupeRelatedVulnerabilities, fmt.Sprintf("%s:%s", primaryVulnerability.Namespace, primaryVulnerability.ID))
	for k := range dedupeRelatedVulnerabilities {
		sortDedupedRelatedVulnerabilities = append(sortDedupedRelatedVulnerabilities, k)
	}
	sort.Strings(sortDedupedRelatedVulnerabilities)
	for _, k := range sortDedupedRelatedVulnerabilities {
		relatedVulnerabilities = append(relatedVulnerabilities, dedupeRelatedVulnerabilities[k])
	}

	return ExplainViewModel{
		PrimaryVulnerability:   primaryVulnerability,
		RelatedVulnerabilities: relatedVulnerabilities,
		MatchedPackages:        explainedPackages,
		URLs:                   dedupeURLs(primaryURL, URLs),
	}
}

func explainMatchDetail(m Match, index int) string {
	if len(m.MatchDetails) <= index {
		return ""
	}
	md := m.MatchDetails[index]
	explanation := ""
	switch md.Type {
	case string(match.CPEMatch):
		explanation = formatCPEExplanation(m)
	case string(match.ExactIndirectMatch):
		sourceName, sourceVersion := sourcePackageNameAndVersion(md)
		explanation = fmt.Sprintf("Note: This CVE is reported against %s (version %s), the %s of this %s package.", sourceName, sourceVersion, nameForUpstream(string(m.Artifact.Type)), m.Artifact.Type)
	}
	return explanation
}
