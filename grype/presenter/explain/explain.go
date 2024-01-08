package explain

import (
	_ "embed"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/template"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/file"
)

//go:embed explain_cve.tmpl
var explainTemplate string

type VulnerabilityExplainer interface {
	ExplainByID(IDs []string) error
	ExplainBySeverity(severity string) error
	ExplainAll() error
}

type ViewModel struct {
	PrimaryVulnerability   models.VulnerabilityMetadata
	RelatedVulnerabilities []models.VulnerabilityMetadata
	MatchedPackages        []*explainedPackage // I think this needs a map of artifacts to explained evidence
	URLs                   []string
}

type viewModelBuilder struct {
	PrimaryMatch   models.Match // The match that seems to be the one we're trying to explain
	RelatedMatches []models.Match
	requestedIDs   []string // the vulnerability IDs the user requested explanations of
}

type Findings map[string]ViewModel

type explainedPackage struct {
	PURL                string
	Name                string
	Version             string
	MatchedOnID         string
	MatchedOnNamespace  string
	IndirectExplanation string
	DirectExplanation   string
	CPEExplanation      string
	Locations           []explainedEvidence
	displayPriority     int // shows how early it should be displayed; direct matches first
}

type explainedEvidence struct {
	Location     string
	ArtifactID   string
	ViaVulnID    string
	ViaNamespace string
}

type vulnerabilityExplainer struct {
	w   io.Writer
	doc *models.Document
}

func NewVulnerabilityExplainer(w io.Writer, doc *models.Document) VulnerabilityExplainer {
	return &vulnerabilityExplainer{
		w:   w,
		doc: doc,
	}
}

var funcs = template.FuncMap{
	"trim": strings.TrimSpace,
}

func (e *vulnerabilityExplainer) ExplainByID(ids []string) error {
	findings, err := Doc(e.doc, ids)
	if err != nil {
		return err
	}
	t := template.Must(template.New("explanation").Funcs(funcs).Parse(explainTemplate))
	for _, id := range ids {
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

func (e *vulnerabilityExplainer) ExplainBySeverity(_ string) error {
	return fmt.Errorf("not implemented")
}

func (e *vulnerabilityExplainer) ExplainAll() error {
	findings, err := Doc(e.doc, nil)
	if err != nil {
		return err
	}
	t := template.Must(template.New("explanation").Funcs(funcs).Parse(explainTemplate))

	return t.Execute(e.w, findings)
}

func Doc(doc *models.Document, requestedIDs []string) (Findings, error) {
	result := make(Findings)
	builders := make(map[string]*viewModelBuilder)
	for _, m := range doc.Matches {
		key := m.Vulnerability.ID
		existing, ok := builders[key]
		if !ok {
			existing = newBuilder(requestedIDs)
			builders[m.Vulnerability.ID] = existing
		}
		existing.WithMatch(m, requestedIDs)
	}
	for _, m := range doc.Matches {
		for _, related := range m.RelatedVulnerabilities {
			key := related.ID
			existing, ok := builders[key]
			if !ok {
				existing = newBuilder(requestedIDs)
				builders[key] = existing
			}
			existing.WithMatch(m, requestedIDs)
		}
	}
	for k, v := range builders {
		result[k] = v.Build()
	}
	return result, nil
}

func newBuilder(requestedIDs []string) *viewModelBuilder {
	return &viewModelBuilder{
		requestedIDs: requestedIDs,
	}
}

// WithMatch adds a match to the builder
// accepting enough information to determine whether the match is a primary match or a related match
func (b *viewModelBuilder) WithMatch(m models.Match, userRequestedIDs []string) {
	if b.isPrimaryAdd(m, userRequestedIDs) {
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

func (b *viewModelBuilder) isPrimaryAdd(candidate models.Match, userRequestedIDs []string) bool {
	if b.PrimaryMatch.Vulnerability.ID == "" {
		return true
	}

	idWasRequested := false
	for _, id := range userRequestedIDs {
		if candidate.Vulnerability.ID == id {
			idWasRequested = true
			break
		}
	}
	// the user didn't ask about this ID, so it's not the primary one
	if !idWasRequested && len(userRequestedIDs) > 0 {
		return false
	}
	// NVD CPEs are somewhat canonical IDs for vulnerabilities, so if the user asked about CVE-YYYY-ID
	// type number, and we have a record from NVD, consider that the primary record.
	if candidate.Vulnerability.Namespace == "nvd:cpe" {
		return true
	}
	// Either the user didn't ask for specific IDs, or the candidate has an ID the user asked for.
	for _, related := range b.PrimaryMatch.RelatedVulnerabilities {
		if related.ID == candidate.Vulnerability.ID {
			return true
		}
	}
	return false
}

func (b *viewModelBuilder) WithPrimaryMatch(m models.Match) *viewModelBuilder {
	b.PrimaryMatch = m
	return b
}

func (b *viewModelBuilder) WithRelatedMatch(m models.Match) *viewModelBuilder {
	b.RelatedMatches = append(b.RelatedMatches, m)
	return b
}

func (b *viewModelBuilder) Build() ViewModel {
	explainedPackages := groupAndSortEvidence(append(b.RelatedMatches, b.PrimaryMatch))

	var relatedVulnerabilities []models.VulnerabilityMetadata
	dedupeRelatedVulnerabilities := make(map[string]models.VulnerabilityMetadata)
	var sortDedupedRelatedVulnerabilities []string
	for _, m := range append(b.RelatedMatches, b.PrimaryMatch) {
		key := fmt.Sprintf("%s:%s", m.Vulnerability.Namespace, m.Vulnerability.ID)
		dedupeRelatedVulnerabilities[key] = m.Vulnerability.VulnerabilityMetadata
		for _, r := range m.RelatedVulnerabilities {
			key := fmt.Sprintf("%s:%s", r.Namespace, r.ID)
			dedupeRelatedVulnerabilities[key] = r
		}
	}

	// delete the primary vulnerability from the related vulnerabilities so it isn't listed twice
	primary := b.primaryVulnerability()
	delete(dedupeRelatedVulnerabilities, fmt.Sprintf("%s:%s", primary.Namespace, primary.ID))
	for k := range dedupeRelatedVulnerabilities {
		sortDedupedRelatedVulnerabilities = append(sortDedupedRelatedVulnerabilities, k)
	}
	sort.Strings(sortDedupedRelatedVulnerabilities)
	for _, k := range sortDedupedRelatedVulnerabilities {
		relatedVulnerabilities = append(relatedVulnerabilities, dedupeRelatedVulnerabilities[k])
	}

	return ViewModel{
		PrimaryVulnerability:   primary,
		RelatedVulnerabilities: relatedVulnerabilities,
		MatchedPackages:        explainedPackages,
		URLs:                   b.dedupeAndSortURLs(primary),
	}
}

func (b *viewModelBuilder) primaryVulnerability() models.VulnerabilityMetadata {
	var primaryVulnerability models.VulnerabilityMetadata
	for _, m := range append(b.RelatedMatches, b.PrimaryMatch) {
		for _, r := range append(m.RelatedVulnerabilities, m.Vulnerability.VulnerabilityMetadata) {
			if r.ID == b.PrimaryMatch.Vulnerability.ID && r.Namespace == "nvd:cpe" {
				primaryVulnerability = r
			}
		}
	}
	if primaryVulnerability.ID == "" {
		primaryVulnerability = b.PrimaryMatch.Vulnerability.VulnerabilityMetadata
	}
	return primaryVulnerability
}

// nolint:funlen
func groupAndSortEvidence(matches []models.Match) []*explainedPackage {
	idsToMatchDetails := make(map[string]*explainedPackage)
	for _, m := range matches {
		key := m.Artifact.ID
		var newLocations []explainedEvidence
		for _, l := range m.Artifact.Locations {
			newLocations = append(newLocations, explainLocation(m, l))
		}
		var directExplanation string
		var indirectExplanation string
		var cpeExplanation string
		var matchTypePriority int
		for i, md := range m.MatchDetails {
			explanation := explainMatchDetail(m, i)
			if explanation != "" {
				switch md.Type {
				case string(match.CPEMatch):
					cpeExplanation = fmt.Sprintf("%s:%s %s", m.Vulnerability.Namespace, m.Vulnerability.ID, explanation)
					matchTypePriority = 1 // cpes are a type of direct match
				case string(match.ExactIndirectMatch):
					indirectExplanation = fmt.Sprintf("%s:%s %s", m.Vulnerability.Namespace, m.Vulnerability.ID, explanation)
					matchTypePriority = 0 // display indirect matches after direct matches
				case string(match.ExactDirectMatch):
					directExplanation = fmt.Sprintf("%s:%s %s", m.Vulnerability.Namespace, m.Vulnerability.ID, explanation)
					matchTypePriority = 2 // exact-direct-matches are high confidence, direct matches; display them first.
				}
			}
		}
		e, ok := idsToMatchDetails[key]
		if !ok {
			e = &explainedPackage{
				PURL:                m.Artifact.PURL,
				Name:                m.Artifact.Name,
				Version:             m.Artifact.Version,
				MatchedOnID:         m.Vulnerability.ID,
				MatchedOnNamespace:  m.Vulnerability.Namespace,
				DirectExplanation:   directExplanation,
				IndirectExplanation: indirectExplanation,
				CPEExplanation:      cpeExplanation,
				Locations:           newLocations,
				displayPriority:     matchTypePriority,
			}
			idsToMatchDetails[key] = e
		} else {
			e.Locations = append(e.Locations, newLocations...)
			if e.CPEExplanation == "" {
				e.CPEExplanation = cpeExplanation
			}
			if e.IndirectExplanation == "" {
				e.IndirectExplanation = indirectExplanation
			}
			e.displayPriority += matchTypePriority
		}
	}
	var sortIDs []string
	for k, v := range idsToMatchDetails {
		sortIDs = append(sortIDs, k)
		dedupeLocations := make(map[string]explainedEvidence)
		for _, l := range v.Locations {
			dedupeLocations[l.Location] = l
		}
		var uniqueLocations []explainedEvidence
		for _, l := range dedupeLocations {
			uniqueLocations = append(uniqueLocations, l)
		}
		sort.Slice(uniqueLocations, func(i, j int) bool {
			if uniqueLocations[i].ViaNamespace == uniqueLocations[j].ViaNamespace {
				return uniqueLocations[i].Location < uniqueLocations[j].Location
			}
			return uniqueLocations[i].ViaNamespace < uniqueLocations[j].ViaNamespace
		})
		v.Locations = uniqueLocations
	}

	sort.Slice(sortIDs, func(i, j int) bool {
		return explainedPackageIsLess(idsToMatchDetails[sortIDs[i]], idsToMatchDetails[sortIDs[j]])
	})
	var explainedPackages []*explainedPackage
	for _, k := range sortIDs {
		explainedPackages = append(explainedPackages, idsToMatchDetails[k])
	}
	return explainedPackages
}

func explainedPackageIsLess(i, j *explainedPackage) bool {
	if i.displayPriority != j.displayPriority {
		return i.displayPriority > j.displayPriority
	}
	return i.Name < j.Name
}

func explainMatchDetail(m models.Match, index int) string {
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
		explanation = fmt.Sprintf("Indirect match; this CVE is reported against %s (version %s), the %s of this %s package.", sourceName, sourceVersion, nameForUpstream(string(m.Artifact.Type)), m.Artifact.Type)
	case string(match.ExactDirectMatch):
		explanation = fmt.Sprintf("Direct match (package name, version, and ecosystem) against %s (version %s).", m.Artifact.Name, m.Artifact.Version)
	}
	return explanation
}

// dedupeAndSortURLs returns a slice of the DataSource fields, deduplicated and sorted
// the NVD and GHSA URL are given special treatment; they return first and second if present
// and the rest are sorted by string sort.
func (b *viewModelBuilder) dedupeAndSortURLs(primaryVulnerability models.VulnerabilityMetadata) []string {
	showFirst := primaryVulnerability.DataSource
	var URLs []string
	URLs = append(URLs, b.PrimaryMatch.Vulnerability.DataSource)
	for _, v := range b.PrimaryMatch.RelatedVulnerabilities {
		URLs = append(URLs, v.DataSource)
	}
	for _, m := range b.RelatedMatches {
		URLs = append(URLs, m.Vulnerability.DataSource)
		for _, v := range m.RelatedVulnerabilities {
			URLs = append(URLs, v.DataSource)
		}
	}
	var result []string
	deduplicate := make(map[string]bool)
	result = append(result, showFirst)
	deduplicate[showFirst] = true
	nvdURL := ""
	ghsaURL := ""
	for _, u := range URLs {
		if strings.HasPrefix(u, "https://nvd.nist.gov/vuln/detail") {
			nvdURL = u
		}
		if strings.HasPrefix(u, "https://github.com/advisories") {
			ghsaURL = u
		}
	}
	if nvdURL != "" && nvdURL != showFirst {
		result = append(result, nvdURL)
		deduplicate[nvdURL] = true
	}
	if ghsaURL != "" && ghsaURL != showFirst {
		result = append(result, ghsaURL)
		deduplicate[ghsaURL] = true
	}

	for _, u := range URLs {
		if _, ok := deduplicate[u]; !ok {
			result = append(result, u)
			deduplicate[u] = true
		}
	}
	return result
}

func explainLocation(match models.Match, location file.Coordinates) explainedEvidence {
	path := location.RealPath
	if javaMeta, ok := match.Artifact.Metadata.(map[string]any); ok {
		if virtPath, ok := javaMeta["virtualPath"].(string); ok {
			path = virtPath
		}
	}
	return explainedEvidence{
		Location:     path,
		ArtifactID:   match.Artifact.ID,
		ViaVulnID:    match.Vulnerability.ID,
		ViaNamespace: match.Vulnerability.Namespace,
	}
}

func formatCPEExplanation(m models.Match) string {
	searchedBy := m.MatchDetails[0].SearchedBy
	if mapResult, ok := searchedBy.(map[string]interface{}); ok {
		if cpes, ok := mapResult["cpes"]; ok {
			if cpeSlice, ok := cpes.([]interface{}); ok {
				if len(cpeSlice) > 0 {
					return fmt.Sprintf("CPE match on `%s`.", cpeSlice[0])
				}
			}
		}
	}
	return ""
}

func sourcePackageNameAndVersion(md models.MatchDetails) (string, string) {
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

func nameForUpstream(typ string) string {
	switch typ {
	case "deb":
		return "origin"
	case "rpm":
		return "source RPM"
	}
	return "upstream"
}
