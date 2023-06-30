package models

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
	PrimaryVulnerability   Vulnerability
	RelatedVulnerabilities []Vulnerability
	MatchedPackages        []*ExplainedPackage
	URLs                   []string
}

type ExplainViewModelBuilder struct {
	PrimaryMatch   Match
	RelatedMatches []Match
}

type ExplainedFindings map[string]ExplainViewModel

type ExplainedPackage struct {
	PURL               string
	Name               string
	Version            string // TODO: is there only going to be one of these?
	Explanation        string
	MatchedOnID        string
	MatchedOnNamespace string
	Locations          []LocatedArtifact
}

func NewExplainedVulnerabilityBuilder() *ExplainViewModelBuilder {
	return &ExplainViewModelBuilder{}
}

func (b *ExplainViewModelBuilder) WithPrimaryVulnerability(m Match) *ExplainViewModelBuilder {
	b.PrimaryMatch = m
	return b
}

func (b *ExplainViewModelBuilder) WithRelatedVulnerability(m Match) *ExplainViewModelBuilder {
	b.RelatedMatches = append(b.RelatedMatches, m)
	return b
}

func (b *ExplainViewModelBuilder) Build() ExplainViewModel {
	primaryURL := b.PrimaryMatch.Vulnerability.DataSource
	URLs := b.PrimaryMatch.Vulnerability.URLs
	for _, m := range b.RelatedMatches {
		URLs = append(URLs, m.Vulnerability.URLs...)
	}

	// pURLsToMatchDetails := make(map[string][]MatchDetails)

	var relatedVulnerabilities []Vulnerability
	for _, m := range b.RelatedMatches {
		relatedVulnerabilities = append(relatedVulnerabilities, m.Vulnerability)
	}

	// var explainedPackages []*ExplainedPackage
	// for k, v := range pURLsToMatchDetails {

	// }

	return ExplainViewModel{
		PrimaryVulnerability:   b.PrimaryMatch.Vulnerability,
		RelatedVulnerabilities: relatedVulnerabilities,
		URLs:                   dedupeURLs(primaryURL, URLs),
	}
}
