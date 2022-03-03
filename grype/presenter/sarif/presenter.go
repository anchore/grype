package sarif

import (
	"fmt"
	"github.com/anchore/grype/internal/log"
	"io"
	"strings"

	s "github.com/owenrumney/go-sarif/sarif"

	v3 "github.com/anchore/grype/grype/db/v3"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/version"
	"github.com/anchore/syft/syft/source"
)

// Presenter holds the data for generating a report and implements the presenter.Presenter interface
type Presenter struct {
	results          match.Matches
	packages         []pkg.Package
	srcMetadata      *source.Metadata
	metadataProvider vulnerability.MetadataProvider
}

// NewPresenter is a *Presenter constructor
func NewPresenter(results match.Matches, packages []pkg.Package, srcMetadata *source.Metadata, metadataProvider vulnerability.MetadataProvider) *Presenter {
	return &Presenter{
		results:          results,
		packages:         packages,
		metadataProvider: metadataProvider,
		srcMetadata:      srcMetadata,
	}
}

// Present creates a SARIF-based report
func (pres *Presenter) Present(output io.Writer) error {
	doc, err := s.New(s.Version210)
	if err != nil {
		return err
	}

	doc.AddRun(&s.Run{
		Tool: s.Tool{
			Driver: &s.ToolComponent{
				Name:    "Anchore Container Vulnerability Report (T0)",
				Version: sp(version.FromBuild().Version),
				Rules:   pres.sarifRules(),
			},
		},
		Results: pres.sarifResults(),
	})

	err = doc.PrettyWrite(output)
	return err
}

// matches returns a set of matches with duplicates removed
func (pres *Presenter) matches() (out []match.Match) {
	ruleIDs := map[string]bool{}

	for _, m := range pres.results.Sorted() {
		ruleID := pres.ruleID(m)

		if ruleIDs[ruleID] {
			log.Infof("skipping duplicate match: %s", m.String())
			continue
		}

		ruleIDs[ruleID] = true

		out = append(out, m)
	}

	return out
}

// sarifRules generates the set of rules to include in this run
func (pres *Presenter) sarifRules() (out []*s.ReportingDescriptor) {
	if pres.results.Count() > 0 {
		for _, m := range pres.matches() {
			ruleID := pres.ruleID(m)

			// Entirely possible to not have any links whatsoever
			link := m.Vulnerability.ID
			meta := pres.metadata(m)
			if meta != nil {
				switch {
				case meta.DataSource != "":
					link = fmt.Sprintf("[%s](%s)", m.Vulnerability.ID, meta.DataSource)
				case len(meta.URLs) > 0:
					link = fmt.Sprintf("[%s](%s)", m.Vulnerability.ID, meta.URLs[0])
				}
			}

			out = append(out, &s.ReportingDescriptor{
				ID: ruleID,
				// Title of the SARIF report
				ShortDescription: &s.MultiformatMessageString{
					Text: sp(pres.shortDescription(m)),
				},
				// Subtitle of the SARIF report
				FullDescription: &s.MultiformatMessageString{
					Text: sp(pres.subtitle(m)),
				},
				Help: pres.helpText(m, link),
			})
		}
	}
	return out
}

func (pres *Presenter) ruleID(m match.Match) string {
	ruleID := fmt.Sprintf("ANCHOREVULN_%s_%s_%s_%s", m.Vulnerability.ID, m.Package.Type, m.Package.Name, m.Package.Version)
	if pres.srcMetadata.Scheme == source.ImageScheme {
		// include the container as part of the rule id so that users can sort by that
		ruleID = fmt.Sprintf("ANCHOREVULN_%s_%s_%s_%s_%s", pres.srcMetadata.ImageMetadata.UserInput, m.Vulnerability.ID, m.Package.Type, m.Package.Name, m.Package.Version)
	}
	return ruleID
}

func (pres *Presenter) helpText(m match.Match, link string) *s.MultiformatMessageString {
	text := fmt.Sprintf("Vulnerability %s\nSeverity: %s\nPackage: %s\nVersion: %s\nFix Version: %s\nType: %s\nLocation: %s\nData Namespace: unknown\nLink: %s",
		m.Vulnerability.ID, pres.severity(m), m.Package.Name, m.Package.Version, fixVersions(m), m.Package.Type, location(m), link,
	)
	markdown := fmt.Sprintf(
		"**Vulnerability %s**\n"+
			"| Severity | Package | Version | Fix Version | Type | Location | Data Namespace | Link |\n"+
			"| --- | --- | --- | --- | --- | --- | --- | --- |\n"+
			"|%s|%s|%s|%s|%s|%s|unknown|%s|\n", m.Vulnerability.ID, pres.severity(m), m.Package.Name, m.Package.Version, fixVersions(m), m.Package.Type, location(m), link,
	)
	return &s.MultiformatMessageString{
		Text:     &text,
		Markdown: &markdown,
	}
}

func location(m match.Match) string {
	if len(m.Package.Locations) > 0 {
		return m.Package.Locations[0].VirtualPath
	}
	// XXX there is room for improvement here, trying to mimick previous behavior
	// If no `dockerfile-path` was provided, and in the improbable situation where there
	// are no locations for the artifact, return 'Dockerfile'
	return "Dockerfile"
}

func (pres *Presenter) severity(m match.Match) string {
	meta := pres.metadata(m)
	if meta == nil {
		return "unknown"
	}
	// FIXME allow severity cutoff specified here?
	// FIXME convert to acs_
	return meta.Severity
}

// metadata returns the matching *vulnerability.Metadata from the provider or nil if not found / error
func (pres *Presenter) metadata(m match.Match) *vulnerability.Metadata {
	meta, _ := pres.metadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.Namespace)
	return meta
}

// subtitle generates a subtitle for the given match
func (pres *Presenter) subtitle(m match.Match) string {
	meta := pres.metadata(m)
	if meta != nil {
		subtitle := meta.Description
		if subtitle != "" {
			return subtitle
		}
	}

	fixVersion := fixVersions(m)
	if fixVersion != "" {
		return fmt.Sprintf("Version %s is affected with an available fix in versions %s", m.Package.Version, fixVersion)
	}

	return fmt.Sprintf("Version %s is affected with no fixes reported yet.", m.Package.Version)
}

func fixVersions(m match.Match) string {
	if m.Vulnerability.Fix.State == v3.FixedState && len(m.Vulnerability.Fix.Versions) > 0 {
		return strings.Join(m.Vulnerability.Fix.Versions, ",")
	}
	return ""
}

func (pres *Presenter) shortDescription(m match.Match) string {
	return fmt.Sprintf("%s %s vulnerability for %s package", m.Vulnerability.ID, pres.severity(m), m.Package.Name)
}

func (pres *Presenter) sarifResults() (out []*s.Result) {
	for _, m := range pres.matches() {
		out = append(out, &s.Result{
			RuleID:         sp(pres.ruleID(m)),
			RuleIndex:      up(0),
			Level:          sp(pres.acsSeverityLevel(m)),
			Message:        pres.resultMessage(m),
			AnalysisTarget: pres.analysisTarget(m),
			Locations: []*s.Location{
				{
					PhysicalLocation: &s.PhysicalLocation{
						ArtifactLocation: &s.ArtifactLocation{
							URI: sp(location(m)),
						},
						// TODO: When grype starts reporting line numbers this will need to get updated
						Region: &s.Region{
							StartLine:   ip(1),
							StartColumn: ip(1),
							EndLine:     ip(1),
							EndColumn:   ip(1),
							ByteOffset:  ip(1),
							ByteLength:  ip(1),
						},
					},
					LogicalLocations: []*s.LogicalLocation{
						{
							FullyQualifiedName: sp("dockerfile"),
						},
					},
				},
			},
			Suppressions: []*s.Suppression{
				{
					Kind: "external",
				},
			},
			BaselineState: sp("unchanged"),
		})
	}
	return out
}

// up returns a uint pointer based on the provided value
func up(i int) *uint {
	u := uint(i)
	return &u
}

// ip returns an int pointer based on the provided value
func ip(i int) *int {
	return &i
}

// sp returns a string pointer based on the provided value
func sp(s string) *string {
	return &s
}

func (pres *Presenter) resultMessage(m match.Match) s.Message {
	path := location(m)
	message := fmt.Sprintf("The path %s reports %s at version %s ", path, m.Package.Name, m.Package.Version)

	if pres.srcMetadata.Scheme == source.DirectoryScheme {
		message = fmt.Sprintf("%s which would result in a vulnerable (%s) package installed", message, m.Package.Type)
	} else {
		message = fmt.Sprintf("%s which is a vulnerable (%s) package installed in the container", message, m.Package.Type)
	}

	return s.Message{
		Text: &message,
		Id:   sp("default"),
	}
}

func (pres *Presenter) analysisTarget(m match.Match) *s.ArtifactLocation {
	uri := location(m)
	return &s.ArtifactLocation{
		URI: &uri,
		// XXX This is possibly a bug. The SARIF schema invalidates this when the index is present because there
		// aren't any other elements present.
		// Index: up(0),
	}
}

func (pres *Presenter) acsSeverityLevel(m match.Match) string {
	// FIXME need an input cutoff param
	// The `severity_cutoff_param` has been lowercased for case-insensitivity at this point, but the
	// severity from the vulnerability will be capitalized, so this must be capitalized again to calculate
	// using the same object
	const cutoff = "High"
	out := "error"
	var severityLevels = map[string]int{
		"Unknown":    0,
		"Negligible": 1,
		"Low":        2,
		"Medium":     3,
		"High":       4,
		"Critical":   5,
	}

	if severityLevels[pres.severity(m)] < severityLevels[cutoff] {
		out = "warning"
	}

	return out
}
