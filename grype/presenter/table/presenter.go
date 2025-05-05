package table

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/olekukonko/tablewriter"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/db/v5/namespace/distro"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
)

const (
	appendSuppressed    = "suppressed"
	appendSuppressedVEX = "suppressed by VEX"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	document       models.Document
	showSuppressed bool
	withColor      bool

	recommendedFixStyle lipgloss.Style
	kevStyle            lipgloss.Style
	criticalStyle       lipgloss.Style
	highStyle           lipgloss.Style
	mediumStyle         lipgloss.Style
	lowStyle            lipgloss.Style
	negligibleStyle     lipgloss.Style
	auxiliaryStyle      lipgloss.Style
	unknownStyle        lipgloss.Style
}

type rows []row

type row struct {
	Name            string
	Version         string
	Fix             string
	PackageType     string
	VulnerabilityID string
	Severity        string
	EPSS            epss
	Risk            string
	Annotation      string
}

type epss struct {
	Score      float64
	Percentile float64
}

func (e epss) String() string {
	percentile := e.Percentile * 100
	switch {
	case percentile == 0:
		return "  N/A"
	case percentile < 0.1:
		return "< 0.1%"
	}
	return fmt.Sprintf("%5.2f", percentile)
}

// NewPresenter is a *Presenter constructor
func NewPresenter(pb models.PresenterConfig, showSuppressed bool) *Presenter {
	withColor := supportsColor()
	fixStyle := lipgloss.NewStyle().Border(lipgloss.Border{Left: "*"}, false, false, false, true)
	if withColor {
		fixStyle = lipgloss.NewStyle()
	}
	return &Presenter{
		document:            pb.Document,
		showSuppressed:      showSuppressed,
		withColor:           withColor,
		recommendedFixStyle: fixStyle,
		negligibleStyle:     lipgloss.NewStyle().Foreground(lipgloss.Color("240")),                          // dark gray
		lowStyle:            lipgloss.NewStyle().Foreground(lipgloss.Color("36")),                           // cyan/teal
		mediumStyle:         lipgloss.NewStyle().Foreground(lipgloss.Color("178")),                          // gold/amber
		highStyle:           lipgloss.NewStyle().Foreground(lipgloss.Color("203")),                          // salmon/light red
		criticalStyle:       lipgloss.NewStyle().Foreground(lipgloss.Color("198")).Bold(true),               // bright pink
		kevStyle:            lipgloss.NewStyle().Foreground(lipgloss.Color("198")).Reverse(true).Bold(true), // white on bright pink
		//kevStyle:       lipgloss.NewStyle().Foreground(lipgloss.Color("198")),             // bright pink
		auxiliaryStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("240")), // dark gray
		unknownStyle:   lipgloss.NewStyle().Foreground(lipgloss.Color("12")),  // light blue
	}
}

// Present creates a JSON-based reporting
func (p *Presenter) Present(output io.Writer) error {
	rs := p.getRows(p.document, p.showSuppressed)

	if len(rs) == 0 {
		_, err := io.WriteString(output, "No vulnerabilities found\n")
		return err
	}

	table := tablewriter.NewWriter(output)
	table.SetHeader([]string{"Name", "Installed", "Fixed-In", "Type", "Vulnerability", "Severity", "EPSS%", "Risk"})
	table.SetAutoWrapText(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetAutoFormatHeaders(true)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)

	table.AppendBulk(rs.Render())

	table.Render()

	return nil
}

func (p *Presenter) getRows(doc models.Document, showSuppressed bool) rows {
	var rs rows

	multipleDistros := false
	existingDistro := ""
	for _, m := range doc.Matches {
		if _, err := distro.FromString(m.Vulnerability.Namespace); err == nil {
			if existingDistro == "" {
				existingDistro = m.Vulnerability.Namespace
			} else if existingDistro != m.Vulnerability.Namespace {
				multipleDistros = true
				break
			}
		}
	}

	// generate rows for matching vulnerabilities
	for _, m := range doc.Matches {
		rs = append(rs, p.newRow(m, "", multipleDistros))
	}

	// generate rows for suppressed vulnerabilities
	if showSuppressed {
		for _, m := range doc.IgnoredMatches {
			msg := appendSuppressed
			if m.AppliedIgnoreRules != nil {
				for i := range m.AppliedIgnoreRules {
					if m.AppliedIgnoreRules[i].Namespace == "vex" {
						msg = appendSuppressedVEX
					}
				}
			}
			rs = append(rs, p.newRow(m.Match, msg, multipleDistros))
		}
	}
	return rs
}

func supportsColor() bool {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("5")).Render("") != ""
}

func (p *Presenter) newRow(m models.Match, extraAnnotation string, showDistro bool) row {
	var annotations []string

	if showDistro {
		if d, err := distro.FromString(m.Vulnerability.Namespace); err == nil {
			annotations = append(annotations, p.auxiliaryStyle.Render(fmt.Sprintf("%s:%s", d.DistroType(), d.Version())))
		}
	}

	if extraAnnotation != "" {
		annotations = append(annotations, p.auxiliaryStyle.Render(extraAnnotation))
	}

	var kev, annotation string
	if len(m.Vulnerability.KnownExploited) > 0 {
		if p.withColor {
			kev = p.kevStyle.Reverse(false).Render("") + p.kevStyle.Render("KEV") + p.kevStyle.Reverse(false).Render("") // ⚡❋◆◉፨⿻⨳✖•
		} else {
			annotations = append([]string{"kev"}, annotations...)
		}
	}

	if len(annotations) > 0 {
		annotation = p.auxiliaryStyle.Render("(") + strings.Join(annotations, p.auxiliaryStyle.Render(", ")) + p.auxiliaryStyle.Render(")")
	}

	if kev != "" {
		annotation = kev + " " + annotation
	}

	return row{
		Name:            m.Artifact.Name,
		Version:         m.Artifact.Version,
		Fix:             p.formatFix(m),
		PackageType:     string(m.Artifact.Type),
		VulnerabilityID: m.Vulnerability.ID,
		Severity:        p.formatSeverity(m.Vulnerability.Severity),
		EPSS:            newEPSS(m.Vulnerability.EPSS),
		Risk:            p.formatRisk(m.Vulnerability.Risk),
		Annotation:      annotation,
	}
}

func newEPSS(es []models.EPSS) epss {
	if len(es) == 0 {
		return epss{}
	}
	return epss{
		Score:      es[0].EPSS,
		Percentile: es[0].Percentile,
	}
}

func (p *Presenter) formatSeverity(severity string) string {
	var severityStyle *lipgloss.Style
	switch strings.ToLower(severity) {
	case "critical":
		severityStyle = &p.criticalStyle
	case "high":
		severityStyle = &p.highStyle
	case "medium":
		severityStyle = &p.mediumStyle
	case "low":
		severityStyle = &p.lowStyle
	case "negligible":
		severityStyle = &p.negligibleStyle
	}

	if severityStyle == nil {
		severityStyle = &p.unknownStyle
	}

	return severityStyle.Render(severity)
}

func (p *Presenter) formatRisk(risk float64) string {
	// TODO: add color to risk?
	switch {
	case risk == 0:
		return "  N/A"
	case risk < 0.1:
		return "< 0.1"
	}
	return fmt.Sprintf("%5.1f", risk)
}

func (p *Presenter) formatFix(m models.Match) string {
	// adjust the model fix state values for better presentation
	switch m.Vulnerability.Fix.State {
	case vulnerability.FixStateWontFix.String():
		return "(won't fix)"
	case vulnerability.FixStateUnknown.String():
		return ""
	}

	// do our best to summarize the fixed versions, de-epmhasize non-recommended versions
	// also, since there is not a lot of screen real estate, we will truncate the list of fixed versions
	// to ~30 characters (or so) to avoid wrapping.
	return p.applyTruncation(
		p.formatVersionsToDisplay(
			m,
			getRecommendedVersions(m),
		),
		m.Vulnerability.Fix.Versions,
	)
}

func getRecommendedVersions(m models.Match) *strset.Set {
	recommended := strset.New()
	for _, d := range m.MatchDetails {
		if d.Fix == nil {
			continue
		}
		if d.Fix.SuggestedVersion != "" {
			recommended.Add(d.Fix.SuggestedVersion)
		}
	}
	return recommended
}

const maxVersionFieldLength = 30

func (p *Presenter) formatVersionsToDisplay(m models.Match, recommendedVersions *strset.Set) []string {
	hasMultipleVersions := len(m.Vulnerability.Fix.Versions) > 1
	shouldHighlightRecommended := hasMultipleVersions && recommendedVersions.Size() > 0

	var currentCharacterCount int
	added := strset.New()
	var vers []string

	for _, v := range m.Vulnerability.Fix.Versions {
		if added.Has(v) {
			continue // skip duplicates
		}

		if shouldHighlightRecommended {
			if recommendedVersions.Has(v) {
				// recommended versions always get added
				added.Add(v)
				currentCharacterCount += len(v)
				vers = append(vers, p.recommendedFixStyle.Render(v))
				continue
			}

			// skip not-necessarily-recommended versions if we're running out of space
			if currentCharacterCount+len(v) > maxVersionFieldLength {
				continue
			}

			// add not-necessarily-recommended versions with auxiliary styling
			currentCharacterCount += len(v)
			added.Add(v)
			vers = append(vers, p.auxiliaryStyle.Render(v))
		} else {
			// when not prioritizing, add all versions
			added.Add(v)
			vers = append(vers, v)
		}
	}

	return vers
}

func (p *Presenter) applyTruncation(formattedVersions []string, allVersions []string) string {
	finalVersions := strings.Join(formattedVersions, p.auxiliaryStyle.Render(", "))

	var characterCount int
	for _, v := range allVersions {
		characterCount += len(v)
	}

	if characterCount > maxVersionFieldLength && len(allVersions) > 1 {
		finalVersions += p.auxiliaryStyle.Render(", ...")
	}

	return finalVersions
}

func (r row) Columns() []string {
	if r.Annotation != "" {
		return []string{r.Name, r.Version, r.Fix, r.PackageType, r.VulnerabilityID, r.Severity, r.EPSS.String(), r.Risk, r.Annotation}
	}
	return []string{r.Name, r.Version, r.Fix, r.PackageType, r.VulnerabilityID, r.Severity, r.EPSS.String(), r.Risk}
}

func (r row) String() string {
	return strings.Join(r.Columns(), "|")
}

func (rs rows) Render() [][]string {
	deduped := rs.Deduplicate()
	out := make([][]string, len(deduped))
	for idx, r := range deduped {
		out[idx] = r.Columns()
	}
	return out
}

func (rs rows) Deduplicate() []row {
	// deduplicate
	seen := map[string]row{}
	var deduped rows

	for _, v := range rs {
		key := v.String()
		if _, ok := seen[key]; ok {
			// dup!
			continue
		}

		seen[key] = v
		deduped = append(deduped, v)
	}

	// render final columns
	return deduped
}
