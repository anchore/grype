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
				Name:           "Anchore Grype Scan",
				Version:        sp("0.90.1"), // sp(version.FromBuild().Version),
				InformationURI: sp("https://github.com/anchore/grype"),
				Rules:          pres.sarifRules(),
			},
		},
		Results: pres.sarifResults(),
	})

	// ??
	doc.Schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

	err = doc.PrettyWrite(output)
	return err
}

// sarifRules generates the set of rules to include in this run
func (pres *Presenter) sarifRules() (out []*s.ReportingDescriptor) {
	if pres.results.Count() > 0 {
		ruleIDs := map[string]bool{}

		for _, m := range pres.results.Sorted() {
			ruleID := pres.ruleID(m)
			if ruleIDs[ruleID] {
				// here, we're only outputting information about the vulnerabilities, not where we matched them
				continue
			}

			ruleIDs[ruleID] = true

			// Entirely possible to not have any links whatsoever
			link := m.Vulnerability.ID
			meta := pres.metadata(m)
			if meta != nil {
				switch {
				case meta.DataSource != "":
					link = fmt.Sprintf("[%s](%s)", meta.ID, meta.DataSource)
				case len(meta.URLs) > 0:
					link = fmt.Sprintf("[%s](%s)", meta.ID, meta.URLs[0])
				}
			}

			out = append(out, &s.ReportingDescriptor{
				ID:      ruleID,
				Name:    sp(ruleName(m)),
				HelpURI: sp("https://github.com/anchore/grype"),
				// Title of the SARIF report
				ShortDescription: &s.MultiformatMessageString{
					Text: sp(pres.shortDescription(m)),
				},
				// Subtitle of the SARIF report
				FullDescription: &s.MultiformatMessageString{
					Text: sp(pres.subtitle(m)),
				},
				Help: pres.helpText(m, link),
				//DefaultConfiguration: &s.ReportingConfiguration{
				//	// FIXME: we may not want to specify this at all
				//	Level: sp(pres.level(m)),
				//},
				Properties: s.Properties{
					//"id":               ruleID,
					//"kind":             "path-problem",
					//"name":             ruleName(m),
					//"problem.severity": pres.level(m),
					// For GitHub reportingDescriptor object:
					// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#reportingdescriptor-object
					"security-severity": pres.severity(m),
				},
			})
		}
	}
	return out
}

func (pres *Presenter) ruleID(m match.Match) string {
	return m.Vulnerability.ID
}

func (pres *Presenter) helpText(m match.Match, link string) *s.MultiformatMessageString {
	// FIXME we shouldn't necessarily be adding a location here, there may be multiple referencing the same vulnerability
	text := fmt.Sprintf("Vulnerability %s\nSeverity: %s\nPackage: %s\nVersion: %s\nFix Version: %s\nType: %s\nLocation: %s\nData Namespace: unknown\nLink: %s",
		m.Vulnerability.ID, pres.severity(m), m.Package.Name, m.Package.Version, fixVersions(m), m.Package.Type, pres.location(m), link,
	)
	markdown := fmt.Sprintf(
		"**Vulnerability %s**\n"+
			"| Severity | Package | Version | Fix Version | Type | Location | Data Namespace | Link |\n"+
			"| --- | --- | --- | --- | --- | --- | --- | --- |\n"+
			"|%s|%s|%s|%s|%s|%s|unknown|%s|\n", m.Vulnerability.ID, pres.severity(m), m.Package.Name, m.Package.Version, fixVersions(m), m.Package.Type, pres.location(m), link,
	)
	return &s.MultiformatMessageString{
		Text:     &text,
		Markdown: &markdown,
	}
}

func (pres *Presenter) location(m match.Match) string {
	var path string
	if len(m.Package.Locations) > 0 {
		l := m.Package.Locations[0]
		switch {
		case l.VirtualPath != "":
			path = l.VirtualPath
		case l.RealPath != "":
			path = l.RealPath
		case l.Coordinates.RealPath != "":
			path = l.Coordinates.RealPath
		}
	}

	switch pres.srcMetadata.Scheme {
	case source.DirectoryScheme:
		if pres.srcMetadata.Path != "" {
			return strings.TrimPrefix(fmt.Sprintf("%s/%s", pres.srcMetadata.Path, path), "./")
		}
		return path
	case source.FileScheme:
		if pres.srcMetadata.Path != "" {
			return fmt.Sprintf("%s:%s", pres.srcMetadata.Path, path)
		}
		return path
	case source.ImageScheme:
		return fmt.Sprintf("%s:%s", pres.srcMetadata.ImageMetadata.UserInput, path)
	}

	if path != "" {
		return path
	}

	// FIXME this was copied from the scan-action:
	// there is room for improvement here, trying to mimick previous behavior
	// If no `dockerfile-path` was provided, and in the improbable situation where there
	// are no locations for the artifact, return 'Dockerfile'
	return "Dockerfile"
}

func (pres *Presenter) level(m match.Match) string {
	meta := pres.metadata(m)
	if meta != nil {
		severity := vulnerability.ParseSeverity(meta.Severity)
		// TODO look at a possible severity filter here
		switch severity {
		case vulnerability.CriticalSeverity, vulnerability.HighSeverity:
			return "error"
		case vulnerability.MediumSeverity, vulnerability.LowSeverity:
			return "warning"
		}
	}
	return "none"
}

func (pres *Presenter) severity(m match.Match) string {
	meta := pres.metadata(m)
	if meta != nil {
		severity := vulnerability.ParseSeverity(meta.Severity)
		switch severity {
		case vulnerability.CriticalSeverity:
			return "critical"
		case vulnerability.HighSeverity:
			return "high"
		case vulnerability.MediumSeverity:
			return "medium"
		}
	}
	return "low"
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
	for _, m := range pres.results.Sorted() {
		out = append(out, &s.Result{
			RuleID:  sp(pres.ruleID(m)),
			Message: pres.resultMessage(m),
			//AnalysisTarget: &s.ArtifactLocation{
			//	URI: sp(pres.location(m)),
			//},
			// FIXME github "requires" partialFingerprints
			// PartialFingerprints: ???
			Locations: []*s.Location{
				{
					PhysicalLocation: &s.PhysicalLocation{
						ArtifactLocation: &s.ArtifactLocation{
							URI: sp(pres.location(m)),
						},
						// TODO: When grype starts reporting line numbers this will need to get updated
						Region: &s.Region{
							StartLine:   ip(1),
							StartColumn: ip(1),
							EndLine:     ip(1),
							EndColumn:   ip(1),
							//ByteOffset:  ip(1),
							//ByteLength:  ip(1),
						},
					},
					//LogicalLocations: []*s.LogicalLocation{
					//	{
					//		FullyQualifiedName: sp("dockerfile"),
					//	},
					//},
				},
			},
		})
	}
	return out
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
	path := pres.location(m)
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

func ruleName(m match.Match) string {
	if len(m.Details) > 0 {
		d := m.Details[0]
		buf := strings.Builder{}
		for _, segment := range []string{string(d.Matcher), string(d.Type)} {
			for _, part := range strings.Split(segment, "-") {
				buf.WriteString(strings.ToUpper(part[:1]))
				buf.WriteString(part[1:])
			}
		}
		return buf.String()
	}
	return m.Vulnerability.ID
}
