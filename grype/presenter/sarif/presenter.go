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

// Present creates a SARIF-based report
func (pres *Presenter) Present(output io.Writer) error {
	doc, err := pres.toSarifReport()
	if err != nil {
		return err
	}
	err = doc.PrettyWrite(output)
	return err
}

// toSarifReport outputs a sarif report object
func (pres *Presenter) toSarifReport() (*s.Report, error) {
	doc, err := s.New(s.Version210)
	if err != nil {
		return nil, err
	}

	v := version.FromBuild().Version
	if v == "[not provided]" {
		// Need a semver to pass the MS SARIF validator
		v = "0.0.0-dev"
	}

	doc.AddRun(&s.Run{
		Tool: s.Tool{
			Driver: &s.ToolComponent{
				Name:           "Anchore Grype Scan",
				Version:        sp(v),
				InformationURI: sp("https://github.com/anchore/grype"),
				Rules:          pres.sarifRules(),
			},
		},
		Results: pres.sarifResults(),
	})

	return doc, nil
}

// sarifRules generates the set of rules to include in this run
func (pres *Presenter) sarifRules() []*s.ReportingDescriptor {
	out := make([]*s.ReportingDescriptor, 0) // make sure we have at least an empty array
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
				Properties: s.Properties{
					// For GitHub reportingDescriptor object:
					// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#reportingdescriptor-object
					"security-severity": pres.securitySeverityValue(m),
				},
			})
		}
	}
	return out
}

// ruleID creates a unique rule ID for a given match
func (pres *Presenter) ruleID(m match.Match) string {
	// TODO if we support configuration, we may want to allow addition of another qualifier such that if multiple
	// vuln scans are run on multiple containers we can identify unique rules for each
	return fmt.Sprintf("%s-%s", m.Vulnerability.ID, m.Package.Name)
}

// helpText gets the help text for a rule, this is displayed in GitHub if you click on the title in a list of vulns
func (pres *Presenter) helpText(m match.Match, link string) *s.MultiformatMessageString {
	// TODO we shouldn't necessarily be adding a location here, there may be multiple referencing the same vulnerability
	// we could instead add some list of all affected locations in the case there are a number found within an image,
	// for example but this might get more complicated if there are multiple vuln scans for a particular branch
	text := fmt.Sprintf("Vulnerability %s\nSeverity: %s\nPackage: %s\nVersion: %s\nFix Version: %s\nType: %s\nLocation: %s\nData Namespace: %s\nLink: %s",
		m.Vulnerability.ID, pres.severityText(m), m.Package.Name, m.Package.Version, fixVersions(m), m.Package.Type, pres.location(m), m.Vulnerability.Namespace, link,
	)
	markdown := fmt.Sprintf(
		"**Vulnerability %s**\n"+
			"| Severity | Package | Version | Fix Version | Type | Location | Data Namespace | Link |\n"+
			"| --- | --- | --- | --- | --- | --- | --- | --- |\n"+
			"| %s  | %s  | %s  | %s  | %s  | %s  | %s  | %s  |\n",
		m.Vulnerability.ID, pres.severityText(m), m.Package.Name, m.Package.Version, fixVersions(m), m.Package.Type, pres.location(m), m.Vulnerability.Namespace, link,
	)
	return &s.MultiformatMessageString{
		Text:     &text,
		Markdown: &markdown,
	}
}

// location the "physical" location of the vuln match
func (pres *Presenter) location(m match.Match) string {
	var path string
	if len(m.Package.Locations) > 0 {
		l := m.Package.Locations[0]
		switch {
		case l.RealPath != "":
			path = l.RealPath
		case l.VirtualPath != "":
			path = l.VirtualPath
		case l.Coordinates.RealPath != "":
			path = l.Coordinates.RealPath
		}
	}

	switch pres.srcMetadata.Scheme {
	case source.DirectoryScheme:
		if pres.srcMetadata.Path != "" {
			return strings.TrimPrefix(fmt.Sprintf("%s/%s", pres.srcMetadata.Path, path), "./")
		}
	case source.FileScheme:
		if pres.srcMetadata.Path != "" {
			return pres.srcMetadata.Path
		}
	}

	return path
}

// locations the locations array is a single "physical" location with potentially multiple logical locations
func (pres *Presenter) locations(m match.Match) []*s.Location {
	var logicalLocations []*s.LogicalLocation
	physicalLocation := pres.location(m)

	switch pres.srcMetadata.Scheme {
	case source.ImageScheme:
		img := pres.srcMetadata.ImageMetadata.UserInput
		for _, l := range m.Package.Locations {
			logicalLocations = append(logicalLocations, &s.LogicalLocation{
				FullyQualifiedName: sp(fmt.Sprintf("%s@%s:%s", img,
					strings.TrimPrefix(l.Coordinates.FileSystemID, "sha256:"),
					l.Coordinates.RealPath)),
				Name: sp(l.Coordinates.RealPath),
			})
		}

		// this is a hack to get results to show up in GitHub, as it requires relative paths for the location
		// but we really won't have any information about what Dockerfile on the filesystem was used to build the image
		// TODO we could add configuration to specify the prefix, a user might want to specify an image name and architecture
		// in the case of multiple vuln scans, for example
		physicalLocation = fmt.Sprintf("image/%s", strings.TrimPrefix(physicalLocation, "/"))
	case source.FileScheme:
		physicalLocation = pres.srcMetadata.Path

		for _, l := range m.Package.Locations {
			logicalLocations = append(logicalLocations, &s.LogicalLocation{
				FullyQualifiedName: sp(fmt.Sprintf("%s:%s", physicalLocation, l.Coordinates.RealPath)),
				Name:               sp(l.Coordinates.RealPath),
			})
		}
	}

	return []*s.Location{
		{
			PhysicalLocation: &s.PhysicalLocation{
				ArtifactLocation: &s.ArtifactLocation{
					URI: sp(physicalLocation),
				},
				// TODO When grype starts reporting line numbers this will need to get updated
				Region: &s.Region{
					StartLine:   ip(1),
					StartColumn: ip(1),
					EndLine:     ip(1),
					EndColumn:   ip(1),
				},
			},
			LogicalLocations: logicalLocations,
		},
	}
}

// severityText provides a textual representation of the severity level of the match
func (pres *Presenter) severityText(m match.Match) string {
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

// securitySeverityValue GitHub uses a numeric severity value to determine whether things are critical, high, etc.
func (pres *Presenter) securitySeverityValue(m match.Match) string {
	meta := pres.metadata(m)
	if meta != nil {
		severity := vulnerability.ParseSeverity(meta.Severity)
		switch severity {
		case vulnerability.CriticalSeverity:
			return "9.0"
		case vulnerability.HighSeverity:
			return "7.0"
		case vulnerability.MediumSeverity:
			return "4.0"
		case vulnerability.LowSeverity:
			return "1.0"
		}
	}
	return "0.0"
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
	return fmt.Sprintf("%s %s vulnerability for %s package", m.Vulnerability.ID, pres.severityText(m), m.Package.Name)
}

func (pres *Presenter) sarifResults() []*s.Result {
	out := make([]*s.Result, 0) // make sure we have at least an empty array
	for _, m := range pres.results.Sorted() {
		out = append(out, &s.Result{
			RuleID:  sp(pres.ruleID(m)),
			Message: pres.resultMessage(m),
			// According to the SARIF spec, I believe we should be using AnalysisTarget.URI to indicate a logical
			// file such as a "Dockerfile" but GitHub does not work well with this
			// FIXME github "requires" partialFingerprints
			// PartialFingerprints: ???
			Locations: pres.locations(m),
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
