package table

import (
	"encoding/csv"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
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
	csvMode        bool

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
	if e.Percentile == 0 {
		return "N/A"
	}

	probability := e.Score * 100
	percentile := e.Percentile * 100

	if probability < 0.1 {
		return fmt.Sprintf("< 0.1%% (%s)", formatPercentileWithSuffix(percentile))
	}

	return fmt.Sprintf("%.1f%% (%s)", probability, formatPercentileWithSuffix(percentile))
}

// CSVString returns a CSV-compatible string representation of EPSS
func (e epss) CSVString() string {
	if e.Percentile == 0 {
		return "N/A"
	}

	probability := e.Score * 100
	percentile := e.Percentile * 100

	if probability < 0.1 {
		return fmt.Sprintf("< 0.1%% (%s)", formatPercentileWithSuffix(percentile))
	}

	return fmt.Sprintf("%.1f%% (%s)", probability, formatPercentileWithSuffix(percentile))
}

func formatPercentileWithSuffix(percentile float64) string {
	p := int(percentile)

	// Handle special cases for 11th, 12th, 13th
	if p%100 >= 11 && p%100 <= 13 {
		return fmt.Sprintf("%dth", p)
	}

	// Handle other cases
	switch p % 10 {
	case 1:
		return fmt.Sprintf("%dst", p)
	case 2:
		return fmt.Sprintf("%dnd", p)
	case 3:
		return fmt.Sprintf("%drd", p)
	default:
		return fmt.Sprintf("%dth", p)
	}
}

// NewPresenter is a *Presenter constructor
func NewPresenter(pb models.PresenterConfig, showSuppressed bool) *Presenter {
	return NewPresenterWithOptions(pb, showSuppressed, false)
}

// NewPresenterWithOptions is a *Presenter constructor with additional options
func NewPresenterWithOptions(pb models.PresenterConfig, showSuppressed bool, csvMode bool) *Presenter {
	withColor := supportsColor()
	fixStyle := lipgloss.NewStyle().Border(lipgloss.Border{Left: "*"}, false, false, false, true)
	if withColor {
		fixStyle = lipgloss.NewStyle()
	}
	// Disable color for CSV mode
	if csvMode {
		withColor = false
	}

	return &Presenter{
		document:            pb.Document,
		showSuppressed:      showSuppressed,
		withColor:           withColor,
		csvMode:             csvMode,
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

// Present creates a table or CSV-based reporting
func (p *Presenter) Present(output io.Writer) error {
	rs := p.getRows(p.document, p.showSuppressed)

	if p.csvMode {
		return p.presentCSV(output, rs)
	}
	return p.presentTable(output, rs)
}

func (p *Presenter) presentCSV(output io.Writer, rs rows) error {
	writer := csv.NewWriter(output)
	defer writer.Flush()

	if err := writer.Write([]string{"Name", "Installed", "Fixed-In", "Type", "Vulnerability", "Severity", "EPSS", "Risk", "Annotations"}); err != nil {
		return err
	}

	if len(rs) == 0 {
		return nil
	}

	for _, row := range rs.RenderCSV() {
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func (p *Presenter) presentTable(output io.Writer, rs rows) error {
	if len(rs) == 0 {
		_, err := io.WriteString(output, "No vulnerabilities found\n")
		return err
	}

	table := newTable(output, []string{"Name", "Installed", "Fixed In", "Type", "Vulnerability", "Severity", "EPSS", "Risk"})

	if err := table.Bulk(rs.Render()); err != nil {
		return fmt.Errorf("failed to add table rows: %w", err)
	}

	return table.Render()
}

func newTable(output io.Writer, columns []string) *tablewriter.Table {
	return tablewriter.NewTable(output,
		tablewriter.WithHeader(columns),
		tablewriter.WithHeaderAutoWrap(tw.WrapNone),
		tablewriter.WithRowAutoWrap(tw.WrapNone),
		tablewriter.WithAutoHide(tw.On),
		tablewriter.WithRenderer(renderer.NewBlueprint()),
		tablewriter.WithBehavior(
			tw.Behavior{
				TrimSpace: tw.On,
				AutoHide:  tw.On,
			},
		),
		tablewriter.WithPadding(
			tw.Padding{
				Right: "  ",
			},
		),
		tablewriter.WithRendition(
			tw.Rendition{
				Symbols: tw.NewSymbols(tw.StyleNone),
				Settings: tw.Settings{
					Lines: tw.Lines{
						ShowTop:        tw.Off,
						ShowBottom:     tw.Off,
						ShowHeaderLine: tw.Off,
						ShowFooterLine: tw.Off,
					},
				},
			},
		),
	)
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
			kev = p.kevStyle.Render(" KEV ") // ⚡❋◆◉፨⿻⨳✖• (requires non-standard fonts:  )
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

	// For CSV mode, use plain text without styling
	severity := m.Vulnerability.Severity
	if !p.csvMode {
		severity = p.formatSeverity(m.Vulnerability.Severity)
	}

	return row{
		Name:            m.Artifact.Name,
		Version:         m.Artifact.Version,
		Fix:             p.formatFix(m),
		PackageType:     string(m.Artifact.Type),
		VulnerabilityID: m.Vulnerability.ID,
		Severity:        severity,
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
		if p.csvMode {
			return "N/A"
		}
		return "  N/A"
	case risk < 0.1:
		return "< 0.1"
	}
	if p.csvMode {
		return fmt.Sprintf("%.1f", risk)
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

func (r row) CSVColumns() []string {
	columns := []string{
		stripANSI(r.Name),
		stripANSI(r.Version),
		stripANSI(r.Fix),
		stripANSI(r.PackageType),
		stripANSI(r.VulnerabilityID),
		stripANSI(r.Severity),
		stripANSI(r.EPSS.CSVString()),
		stripANSI(r.Risk),
		stripANSI(r.Annotation),
	}

	return columns
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

func (rs rows) RenderCSV() [][]string {
	deduped := rs.Deduplicate()
	out := make([][]string, len(deduped))
	for idx, r := range deduped {
		out[idx] = r.CSVColumns()
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

// stripANSI removes ANSI escape sequences from a string
func stripANSI(str string) string {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(str, "")
}
