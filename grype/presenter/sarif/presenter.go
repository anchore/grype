package sarif

import (
	"fmt"
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

// Present creates a SARIF-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	doc, err := s.New(s.Version210)
	doc.AddRun(&s.Run{
		Tool: s.Tool{
			Driver: &s.ToolComponent{
				Name:    "Anchore Container Vulnerability Report (T0)",
				Version: sp(version.FromBuild().Version),
				Rules:   pres.toSarifRules(),
			},
		},
		Results: pres.toSarifResults(),
	})

	err = doc.PrettyWrite(output)
	return err
}

func (pres *Presenter) toSarifRules() (out []*s.ReportingDescriptor) {
	ruleIDs := map[string]bool{}
	if pres.results.Count() > 0 {
		for _, v := range pres.results.Sorted() {
			ruleID := pres.ruleID(v)

			if ruleIDs[ruleID] {
				continue
			}

			ruleIDs[ruleID] = true

			// Entirely possible to not have any links whatsoever
			link := v.Vulnerability.ID
			md, err := pres.metadataProvider.GetMetadata(v.Vulnerability.ID, v.Vulnerability.Namespace)
			if err != nil {
				switch {
				case md.DataSource != "":
					link = fmt.Sprintf("[%s](%s)", v.Vulnerability.ID, md.DataSource)
				case len(md.URLs) > 0:
					link = fmt.Sprintf("[%s](%s)", v.Vulnerability.ID, md.URLs[0])
				}
			}

			out = append(out, &s.ReportingDescriptor{
				ID: ruleID,
				// Title of the SARIF report
				ShortDescription: &s.MultiformatMessageString{
					Text: sp(pres.shortDescription(v)),
				},
				// Subtitle of the SARIF report
				FullDescription: &s.MultiformatMessageString{
					Text: sp(subtitle(v)),
				},
				Help: pres.helpText(v, link),
			})
		}
	}
	return
}

func (pres *Presenter) ruleID(v match.Match) string {
	ruleID := fmt.Sprintf("ANCHOREVULN_%s_%s_%s_%s", v.Vulnerability.ID, v.Package.Type, v.Package.Name, v.Package.Version)
	if pres.srcMetadata.Scheme == source.ImageScheme {
		// include the container as part of the rule id so that users can sort by that
		ruleID = fmt.Sprintf("ANCHOREVULN_%s_%s_%s_%s_%s", pres.srcMetadata.ImageMetadata.UserInput, v.Vulnerability.ID, v.Package.Type, v.Package.Name, v.Package.Version)
	}
	return ruleID
}

func (pres *Presenter) helpText(v match.Match, link string) *s.MultiformatMessageString {
	text := fmt.Sprintf("Vulnerability %s\nSeverity: %s\nPackage: %s\nVersion: %s\nFix Version: %s\nType: %s\nLocation: %s\nData Namespace: unknown\nLink: %s",
		v.Vulnerability.ID, pres.severity(v), v.Package.Name, v.Package.Version, fixVersions(v), v.Package.Type, v.Package.Locations[0].VirtualPath, link,
	)
	markdown := fmt.Sprintf(
		"**Vulnerability %s**\n"+
			"| Severity | Package | Version | Fix Version | Type | Location | Data Namespace | Link |\n"+
			"| --- | --- | --- | --- | --- | --- | --- | --- |\n"+
			"|%s|%s|%s|%s|%s|%s|unknown|%s|\n", v.Vulnerability.ID, pres.severity(v), v.Package.Name, v.Package.Version, fixVersions(v), v.Package.Type, v.Package.Locations[0].VirtualPath, link,
	)
	return &s.MultiformatMessageString{
		Text:     &text,
		Markdown: &markdown,
	}
}

func (pres *Presenter) severity(v match.Match) string {
	md, err := pres.metadataProvider.GetMetadata(v.Vulnerability.ID, v.Vulnerability.Namespace)
	if err != nil {
		return "unknown"
	}
	// FIXME allow severity cutoff specified here?
	// FIXME convert to acs_
	return md.Severity
}

func subtitle(v match.Match) string {
	subtitle := v.Vulnerability.String()
	if subtitle != "" {
		return subtitle
	}

	subtitle = fixVersions(v)
	if subtitle != "" {
		return fmt.Sprintf("Version %s is affected with an available fix in versions %s", v.Package.Version, subtitle)
	}

	return fmt.Sprintf("Version %s is affected with no fixes reported yet.", v.Package.Version)
}

func fixVersions(v match.Match) string {
	if v.Vulnerability.Fix.State == v3.FixedState && len(v.Vulnerability.Fix.Versions) > 0 {
		return strings.Join(v.Vulnerability.Fix.Versions, ",")
	}
	return ""
}

func (pres *Presenter) shortDescription(v match.Match) string {
	return fmt.Sprintf("%s %s vulnerability for %s package", v.Vulnerability.ID, pres.severity(v), v.Package.Name)
}

func (pres *Presenter) toSarifResults() (out []*s.Result) {
	for _, v := range pres.results.Sorted() {
		out = append(out, &s.Result{
			RuleID:         sp(pres.ruleID(v)),
			RuleIndex:      up(0),
			Level:          sp(pres.acsSeverityLevel(v)),
			Message:        pres.resultMessage(v),
			AnalysisTarget: pres.analysisTarget(v),
			Locations: []*s.Location{
				{
					PhysicalLocation: &s.PhysicalLocation{
						ArtifactLocation: &s.ArtifactLocation{
							URI: sp(getLocation(v)),
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
	return
}

func up(i int) *uint {
	u := uint(i)
	return &u
}

func ip(i int) *int {
	return &i
}

func sp(s string) *string {
	return &s
}

func (pres *Presenter) resultMessage(v match.Match) s.Message {
	path := getLocation(v)
	message := fmt.Sprintf("The path %s reports %s at version %s ", path, v.Package.Name, v.Package.Version)

	if pres.srcMetadata.Scheme == source.DirectoryScheme {
		message = fmt.Sprintf("%s which would result in a vulnerable (%s) package installed", message, v.Package.Type)
	} else {
		message = fmt.Sprintf("%s which is a vulnerable (%s) package installed in the container", message, v.Package.Type)
	}

	return s.Message{
		Text: &message,
		Id:   sp("default"),
	}
}

func getLocation(v match.Match) string {
	if len(v.Package.Locations) > 0 {
		// If the scan was against a directory, the location will be a string
		location := v.Package.Locations[0]
		return location.VirtualPath
	}
	// XXX there is room for improvement here, trying to mimick previous behavior
	// If no `dockerfile-path` was provided, and in the improbable situation where there
	// are no locations for the artifact, return 'Dockerfile'
	return "Dockerfile"

}

func (pres *Presenter) analysisTarget(v match.Match) *s.ArtifactLocation {
	uri := getLocation(v)
	return &s.ArtifactLocation{
		URI: &uri,
		// XXX This is possibly a bug. The SARIF schema invalidates this when the index is present because there
		// aren't any other elements present.
		//"index": 0
	}
}

func (pres *Presenter) acsSeverityLevel(v match.Match) string {
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

	if severityLevels[pres.severity(v)] < severityLevels[cutoff] {
		out = "warning"
	}

	return out
}
