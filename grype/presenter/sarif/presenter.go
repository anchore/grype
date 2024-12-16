package sarif

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/owenrumney/go-sarif/sarif"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

// Presenter holds the data for generating a report and implements the presenter.Presenter interface
type Presenter struct {
	id               clio.Identification
	results          match.Matches
	packages         []pkg.Package
	src              *source.Description
	metadataProvider vulnerability.MetadataProvider
}

// NewPresenter is a *Presenter constructor
func NewPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		id:               pb.ID,
		results:          pb.Matches,
		packages:         pb.Packages,
		metadataProvider: pb.MetadataProvider,
		src:              pb.Context.Source,
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
func (pres *Presenter) toSarifReport() (*sarif.Report, error) {
	doc, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, err
	}

	v := pres.id.Version
	if v == "[not provided]" || v == "" {
		// Need a semver to pass the MS SARIF validator
		v = "0.0.0-dev"
	}

	doc.AddRun(&sarif.Run{
		Tool: sarif.Tool{
			Driver: &sarif.ToolComponent{
				Name:           pres.id.Name,
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
func (pres *Presenter) sarifRules() (out []*sarif.ReportingDescriptor) {
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

			descriptor := sarif.ReportingDescriptor{
				ID:      ruleID,
				Name:    sp(ruleName(m)),
				HelpURI: sp("https://github.com/anchore/grype"),
				// Title of the SARIF report
				ShortDescription: &sarif.MultiformatMessageString{
					Text: sp(pres.shortDescription(m)),
				},
				// Subtitle of the SARIF report
				FullDescription: &sarif.MultiformatMessageString{
					Text: sp(pres.subtitle(m)),
				},
				Help: pres.helpText(m, link),
				Properties: sarif.Properties{
					// For GitHub reportingDescriptor object:
					// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#reportingdescriptor-object
					"security-severity": pres.securitySeverityValue(m),
				},
			}

			if len(m.Package.PURL) != 0 {
				descriptor.Properties["purls"] = []string{m.Package.PURL}
			}

			out = append(out, &descriptor)
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
func (pres *Presenter) helpText(m match.Match, link string) *sarif.MultiformatMessageString {
	// TODO we shouldn't necessarily be adding a location here, there may be multiple referencing the same vulnerability
	// we could instead add some list of all affected locations in the case there are a number found within an image,
	// for example but this might get more complicated if there are multiple vuln scans for a particular branch
	text := fmt.Sprintf("Vulnerability %s\nSeverity: %s\nPackage: %s\nVersion: %s\nFix Version: %s\nType: %s\nLocation: %s\nData Namespace: %s\nLink: %s",
		m.Vulnerability.ID, pres.severityText(m), m.Package.Name, m.Package.Version, fixVersions(m), m.Package.Type, pres.packagePath(m.Package), m.Vulnerability.Namespace, link,
	)
	markdown := fmt.Sprintf(
		"**Vulnerability %s**\n"+
			"| Severity | Package | Version | Fix Version | Type | Location | Data Namespace | Link |\n"+
			"| --- | --- | --- | --- | --- | --- | --- | --- |\n"+
			"| %s  | %s  | %s  | %s  | %s  | %s  | %s  | %s  |\n",
		m.Vulnerability.ID, pres.severityText(m), m.Package.Name, m.Package.Version, fixVersions(m), m.Package.Type, pres.packagePath(m.Package), m.Vulnerability.Namespace, link,
	)
	return &sarif.MultiformatMessageString{
		Text:     &text,
		Markdown: &markdown,
	}
}

// packagePath attempts to get the relative path of the package to the "scan root"
func (pres *Presenter) packagePath(p pkg.Package) string {
	locations := p.Locations.ToSlice()
	if len(locations) > 0 {
		return pres.locationPath(locations[0])
	}
	return pres.inputPath()
}

// inputPath returns a friendlier relative path or absolute path depending on the input, not prefixed by . or ./
func (pres *Presenter) inputPath() string {
	if pres.src == nil {
		return ""
	}
	var inputPath string
	switch m := pres.src.Metadata.(type) {
	case source.FileMetadata:
		inputPath = m.Path
	case source.DirectoryMetadata:
		inputPath = m.Path
	default:
		return ""
	}
	inputPath = strings.TrimPrefix(inputPath, "./")
	if inputPath == "." {
		return ""
	}
	return inputPath
}

// locationPath returns a path for the location, relative to the cwd
func (pres *Presenter) locationPath(l file.Location) string {
	path := l.Path()
	in := pres.inputPath()
	path = strings.TrimPrefix(path, "./")
	// trimmed off any ./ and accounted for dir:. for both path and input path
	if pres.src != nil {
		_, ok := pres.src.Metadata.(source.DirectoryMetadata)
		if ok {
			if filepath.IsAbs(path) || in == "" {
				return path
			}
			// return a path relative to the cwd, if it's not absolute
			return fmt.Sprintf("%s/%s", in, path)
		}
	}

	return path
}

// locations the locations array is a single "physical" location with potentially multiple logical locations
func (pres *Presenter) locations(m match.Match) []*sarif.Location {
	physicalLocation := pres.packagePath(m.Package)

	var logicalLocations []*sarif.LogicalLocation

	switch metadata := pres.src.Metadata.(type) {
	case source.ImageMetadata:
		img := metadata.UserInput
		locations := m.Package.Locations.ToSlice()
		for _, l := range locations {
			trimmedPath := strings.TrimLeft(pres.locationPath(l), "/")
			logicalLocations = append(logicalLocations, &sarif.LogicalLocation{
				FullyQualifiedName: sp(fmt.Sprintf("%s@%s:/%s", img, l.FileSystemID, trimmedPath)),
				Name:               sp(l.RealPath),
			})
		}

		// GitHub requires paths for the location, but we really don't have any information about what
		// file(s) these originated from in the repository. e.g. which Dockerfile was used to build an image,
		// so we just use a short path-compatible image name here, not the entire user input as it may include
		// sha and/or tags which are likely to change between runs and aren't really necessary for a general
		// path to find file where the package originated
		physicalLocation = fmt.Sprintf("%s/%s", imageShortPathName(pres.src), physicalLocation)
	case source.FileMetadata:
		locations := m.Package.Locations.ToSlice()
		for _, l := range locations {
			logicalLocations = append(logicalLocations, &sarif.LogicalLocation{
				FullyQualifiedName: sp(fmt.Sprintf("%s:/%s", metadata.Path, pres.locationPath(l))),
				Name:               sp(l.RealPath),
			})
		}
	case source.DirectoryMetadata:
		// DirectoryScheme is already handled, with input prepended if needed
	}

	return []*sarif.Location{
		{
			PhysicalLocation: &sarif.PhysicalLocation{
				ArtifactLocation: &sarif.ArtifactLocation{
					URI: sp(physicalLocation),
				},
				// TODO When grype starts reporting line numbers this will need to get updated
				Region: &sarif.Region{
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

// cvssScore attempts to get the best CVSS score that our vulnerability data contains
func (pres *Presenter) cvssScore(v vulnerability.Vulnerability) float64 {
	var all []*vulnerability.Metadata

	meta, err := pres.metadataProvider.VulnerabilityMetadata(v.Reference)
	if err == nil && meta != nil {
		all = append(all, meta)
	}

	for _, related := range v.RelatedVulnerabilities {
		meta, err = pres.metadataProvider.VulnerabilityMetadata(related)
		if err == nil && meta != nil {
			all = append(all, meta)
		}
	}

	score := -1.0

	// first check vendor-specific entries
	for _, m := range all {
		if m.Namespace == "nvd:cpe" {
			continue
		}
		for _, cvss := range m.Cvss {
			if cvss.Metrics.BaseScore > score {
				score = cvss.Metrics.BaseScore
			}
		}
	}

	if score > 0 {
		return score
	}

	// next, check nvd entries
	for _, m := range all {
		for _, cvss := range m.Cvss {
			if cvss.Metrics.BaseScore > score {
				score = cvss.Metrics.BaseScore
			}
		}
	}

	return score
}

// securitySeverityValue GitHub security-severity property uses a numeric severity value to determine whether things
// are critical, high, etc.; this converts our vulnerability to a value within the ranges
func (pres *Presenter) securitySeverityValue(m match.Match) string {
	meta := pres.metadata(m)
	if meta != nil {
		// this corresponds directly to the CVSS score, so we return this if we have it
		score := pres.cvssScore(m.Vulnerability)
		if score > 0 {
			return fmt.Sprintf("%.1f", score)
		}
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
	meta, _ := pres.metadataProvider.VulnerabilityMetadata(m.Vulnerability.Reference)
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
	if m.Vulnerability.Fix.State == vulnerability.FixStateFixed && len(m.Vulnerability.Fix.Versions) > 0 {
		return strings.Join(m.Vulnerability.Fix.Versions, ",")
	}
	return ""
}

func (pres *Presenter) shortDescription(m match.Match) string {
	return fmt.Sprintf("%s %s vulnerability for %s package", m.Vulnerability.ID, pres.severityText(m), m.Package.Name)
}

func (pres *Presenter) sarifResults() []*sarif.Result {
	out := make([]*sarif.Result, 0) // make sure we have at least an empty array
	for _, m := range pres.results.Sorted() {
		out = append(out, &sarif.Result{
			RuleID:  sp(pres.ruleID(m)),
			Message: pres.resultMessage(m),
			// According to the SARIF spec, it may be correct to use AnalysisTarget.URI to indicate a logical
			// file such as a "Dockerfile" but GitHub does not work well with this
			// GitHub requires partialFingerprints to upload to the API; these are automatically filled in
			// when using the CodeQL upload action. See: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#providing-data-to-track-code-scanning-alerts-across-runs
			PartialFingerprints: pres.partialFingerprints(m),
			Locations:           pres.locations(m),
		})
	}
	return out
}

// ip returns an int pointer based on the provided value
func ip(i int) *int {
	return &i
}

// sp returns a string pointer based on the provided value
func sp(sarif string) *string {
	return &sarif
}

func (pres *Presenter) resultMessage(m match.Match) sarif.Message {
	path := pres.packagePath(m.Package)
	src := pres.inputPath()
	switch meta := pres.src.Metadata.(type) {
	case source.ImageMetadata:
		src = fmt.Sprintf("in image %s at: %s", meta.UserInput, path)
	case source.FileMetadata, source.DirectoryMetadata:
		src = fmt.Sprintf("at: %s", path)
	case pkg.PURLLiteralMetadata:
		src = fmt.Sprintf("from purl literal %q", meta.PURL)
	case pkg.PURLFileMetadata:
		src = fmt.Sprintf("from purl file %s", meta.Path)
	}
	message := fmt.Sprintf("A %s vulnerability in %s package: %s, version %s was found %s",
		pres.severityText(m), m.Package.Type, m.Package.Name, m.Package.Version, src)

	return sarif.Message{
		Text: &message,
	}
}

func (pres *Presenter) partialFingerprints(m match.Match) map[string]any {
	p := m.Package
	hasher := sha256.New()
	if meta, ok := pres.src.Metadata.(source.ImageMetadata); ok {
		hashWrite(hasher, pres.src.Name, meta.Architecture, meta.OS)
	}
	hashWrite(hasher, string(p.Type), p.Name, p.Version, pres.packagePath(p))
	return map[string]any{
		// this is meant to include <hash>:<line>, but there isn't line information here, so just include :1
		"primaryLocationLineHash": fmt.Sprintf("%x:1", hasher.Sum([]byte{})),
	}
}

func hashWrite(hasher hash.Hash, values ...string) {
	for _, value := range values {
		_, _ = hasher.Write([]byte(value))
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

var nonPathChars = regexp.MustCompile("[^a-zA-Z0-9-_.]")

// imageShortPathName returns path-compatible text describing the image. if the image name is the form
// some/path/to/image, it will return the image portion of the name.
func imageShortPathName(s *source.Description) string {
	imageName := s.Name
	parts := strings.Split(imageName, "/")
	imageName = parts[len(parts)-1]
	imageName = nonPathChars.ReplaceAllString(imageName, "")
	return imageName
}
